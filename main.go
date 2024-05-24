package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/dtylman/scp"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
)

const (
	// DirectionUpload specifies an upload of local files to a remote target.
	DirectionUpload = "upload"
	// 是否以zip方式上传
	DirectionUploadZip = "uploadZip"
	// DirectionDownload specifies the download of remote files to a local target.
	DirectionDownload = "download"
)

type copyFunc func(client *ssh.Client, source string, target string) (int64, error)

func main() {
	for idx, args := range os.Args {
		if idx == 1 && args == "test" {
			err := godotenv.Load()
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	// Parse timeout.
	actionTimeout, err := time.ParseDuration(os.Getenv("ACTION_TIMEOUT"))
	if err != nil {
		log.Fatalf("❌ Failed to parse action timeout: %v", err)
	}

	// Stop the action if it takes longer that the specified timeout.
	actionTimeoutTimer := time.NewTimer(actionTimeout)
	go func() {
		<-actionTimeoutTimer.C
		log.Fatalf("❌ Failed to run action: %v", errors.New("action timed out"))
		os.Exit(1)
	}()

	// Parse direction.
	direction := os.Getenv("DIRECTION")
	if direction != DirectionDownload && direction != DirectionUploadZip && direction != DirectionUpload {
		log.Fatalf("❌ Failed to parse direction: %v", errors.New("direction must be either upload or download"))
	}

	// Parse timeout.
	timeout, err := time.ParseDuration(os.Getenv("TIMEOUT"))
	if err != nil {
		log.Fatalf("❌ Failed to parse timeout: %v", err)
	}

	// Parse target host.
	targetHost := os.Getenv("HOST")
	if targetHost == "" {
		log.Fatalf("❌ Failed to parse target host: %v", errors.New("target host must not be empty"))
	}

	// Create configuration for SSH target.
	targetConfig := &ssh.ClientConfig{
		Timeout:         timeout,
		User:            os.Getenv("USERNAME"),
		Auth:            ConfigureAuthentication(os.Getenv("KEY"), os.Getenv("PASSPHRASE"), os.Getenv("INSECURE_PASSWORD")),
		HostKeyCallback: ConfigureHostKeyCallback(os.Getenv("FINGERPRINT"), os.Getenv("INSECURE_IGNORE_FINGERPRINT")),
	}

	// Configure target address.
	targetAddress := os.Getenv("HOST") + ":" + os.Getenv("PORT")

	// Initialize target SSH client.
	var targetClient *ssh.Client

	// Check if a proxy should be used.
	if proxyHost := os.Getenv("PROXY_HOST"); proxyHost != "" {
		// Create SSH config for SSH proxy.
		proxyConfig := &ssh.ClientConfig{
			Timeout:         timeout,
			User:            os.Getenv("PROXY_USERNAME"),
			Auth:            ConfigureAuthentication(os.Getenv("PROXY_KEY"), os.Getenv("PROXY_PASSPHRASE"), os.Getenv("INSECURE_PROXY_PASSWORD")),
			HostKeyCallback: ConfigureHostKeyCallback(os.Getenv("PROXY_FINGERPRINT"), os.Getenv("INSECURE_PROXY_IGNORE_FINGERPRINT")),
		}

		// Establish SSH session to proxy host.
		proxyAddress := proxyHost + ":" + os.Getenv("PROXY_PORT")
		proxyClient, err := ssh.Dial("tcp", proxyAddress, proxyConfig)
		if err != nil {
			log.Fatalf("❌ Failed to connect to proxy: %v", err)
		}
		defer proxyClient.Close()

		// Create a TCP connection to from the proxy host to the target.
		netConn, err := proxyClient.Dial("tcp", targetAddress)
		if err != nil {
			log.Fatalf("❌ Failed to dial to target: %v", err)
		}

		targetConn, channel, req, err := ssh.NewClientConn(netConn, targetAddress, targetConfig)
		if err != nil {
			log.Fatalf("❌ Failed to connect to target: %v", err)
		}

		targetClient = ssh.NewClient(targetConn, channel, req)
	} else {
		if targetClient, err = ssh.Dial("tcp", targetAddress, targetConfig); err != nil {
			log.Fatalf("❌ Failed to connect to target: %v", err)
		}
	}
	defer targetClient.Close()

	Copy(targetClient)

}

// Copy transfers files between remote host and local machine.
func Copy(client *ssh.Client) {
	sourceFiles := strings.Split(os.Getenv("SOURCE"), "\n")
	targetFileOrFolder := strings.TrimSpace(os.Getenv("TARGET"))
	direction := os.Getenv("DIRECTION")

	var copy copyFunc
	var emoji string
	if direction == DirectionDownload {
		copy = scp.CopyFrom
		emoji = "🔽"
	}

	if direction == DirectionUpload {
		copy = scp.CopyTo
		emoji = "🔼"
	}

	if direction == DirectionUploadZip {
		copy = scp.CopyTo
		emoji = "🔼"
		// 打包zip并把路径重置为zip路径
		log.Println("📑 tar.gz压缩(Tar compressed file)")
		var src = sourceFiles[0]
		// var dst = fmt.Sprintf("%s.tar.gz", src)
		var dst = "./tar_test.zip"

		// err := tarDecompress(src, dst)
		// path, err := Tar(src, dst)
		// if err != nil {
		// 	log.Fatalf("❌ Failed to %s file from remote: %v", os.Getenv("DIRECTION"), err)
		// }

		exclude := os.Getenv("EXCLUDE")

		excludeArr := strings.Split(exclude, ",")

		args := []string{"-r", dst, src} //  "-x", "test/1.txt", "-x", "test/2.txt"

		for _, v := range excludeArr {
			// excludeStr += " -x='" + v + "'"
			args = append(args, "-x")
			args = append(args, v)
		}

		err := Zipit(src, dst, exclude)
		if err != nil {
			log.Fatalf("❌ Failed to %s file from remote,install zip: %v", os.Getenv("DIRECTION"), err)
		}

		// fmt.Println(args)
		// // -x "/dist/.webpackFSCache/*"
		// cmdInstallZip := exec.Command("apt", "-y", "install", "zip")
		// var outzip bytes.Buffer
		// cmdInstallZip.Stdout = &outzip
		// cmdInstallZip.Env = append(os.Environ(),
		// 	"FOO=duplicate_value", // 重复被忽略
		// 	"FOO=actual_value",    // 实际被使用
		// )
		// err := cmdInstallZip.Run()
		// if err != nil {
		// 	log.Fatalf("❌ Failed to %s file from remote,install zip: %v", os.Getenv("DIRECTION"), err)
		// }

		// cmd := exec.Command("zip", args...)
		// // cmd := exec.Command("zip", "-r", dst, src, "-x", "test/1.txt", "-x", "test/2.txt")
		// var out bytes.Buffer
		// cmd.Stdout = &out
		// cmd.Env = append(os.Environ(),
		// 	"FOO=duplicate_value", // 重复被忽略
		// 	"FOO=actual_value",    // 实际被使用
		// )
		// err = cmd.Run()
		// if err != nil {
		// 	log.Fatalf("❌ Failed to %s file from remote: %v", os.Getenv("DIRECTION"), err)
		// }
		// fmt.Printf("Out: %q\n", out.String())

		// 解压测试
		// if err := UnTar(path, "./un_tar_test"); err != nil {
		// 	log.Fatalf("❌ Failed to %s file from remote: %v", os.Getenv("DIRECTION"), err)
		// }

		sourceFiles[0] = dst

	}

	log.Printf("%s %sing ...\n", emoji, strings.Title(direction))
	if len(sourceFiles) == 1 {
		// Rename file if there is only one source file.
		if _, err := copy(client, sourceFiles[0], targetFileOrFolder); err != nil {
			log.Fatalf("❌ Failed to %s file from remote: %v", os.Getenv("DIRECTION"), err)
		}
		log.Println("📑 " + sourceFiles[0] + " >> " + targetFileOrFolder)

		log.Println("📡 Transferred 1 file")

		// // tar.gz copy 完成后要进行解压
		// if direction == DirectionUploadZip {
		// 	paths, _ := filepath.Split(targetFileOrFolder)
		// 	// 解压到哪里
		// 	// unPath := strings.Replace(targetFileOrFolder, ".tar.gz", "/", -1)
		// 	// 解压测试
		// 	if err := UnTar(targetFileOrFolder, paths); err != nil {
		// 		log.Fatalf("❌ Failed to %s file from remote: %v", os.Getenv("DIRECTION"), err)
		// 	}
		// }

		err := SSHUnZip(client, targetFileOrFolder)
		if err != nil {
			log.Fatalf("❌ Failed to %s file from remote: %v", os.Getenv("DIRECTION"), err)
		}
	} else {
		transferredFiles := int64(0)

		for _, sourceFile := range sourceFiles {
			_, file := path.Split(sourceFile)
			targetFile := path.Join(targetFileOrFolder, file)

			if _, err := copy(client, sourceFile, targetFile); err != nil {
				log.Fatalf("❌ Failed to %s file from remote: %v", os.Getenv("DIRECTION"), err)
			}
			log.Println("📑 " + sourceFile + " >> " + targetFile)

			transferredFiles += 1
		}

		log.Printf("📡 Transferred %d files\n", transferredFiles)
	}
}

// ConfigureAuthentication configures the authentication method.
func ConfigureAuthentication(key string, passphrase string, password string) []ssh.AuthMethod {
	// Create signer for public key authentication method.
	auth := make([]ssh.AuthMethod, 1)

	if key != "" {
		var err error
		var targetSigner ssh.Signer

		if passphrase != "" {
			targetSigner, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(passphrase))
		} else {
			targetSigner, err = ssh.ParsePrivateKey([]byte(key))
		}
		if err != nil {
			log.Fatalf("❌ Failed to parse private key: %v", err)
		}

		// Configure public key authentication.
		auth[0] = ssh.PublicKeys(targetSigner)
	} else if password != "" {
		// Fall back to password authentication.
		auth[0] = ssh.Password(password)
		log.Println("⚠️ Using a password for authentication is insecure!")
		log.Println("⚠️ Please consider using public key authentication!")
	} else {
		log.Fatal("❌ Failed to configure authentication method: missing credentials")
	}

	return auth
}

// ConfigureHostKeyCallback configures the SSH host key verification callback.
// Unless the `skip` option is set to `string("true")` it will return a function,
// which verifies the host key against the specified ssh key fingerprint.
func ConfigureHostKeyCallback(expected string, skip string) ssh.HostKeyCallback {
	if skip == "true" {
		log.Println("⚠️ Skipping host key verification is insecure!")
		log.Println("⚠️ This allows for person-in-the-middle attacks!")
		log.Println("⚠️ Please consider using host key verification!")
		return ssh.InsecureIgnoreHostKey()
	}

	return func(hostname string, remote net.Addr, pubKey ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(pubKey)
		if fingerprint != expected {
			return errors.New("fingerprint mismatch: server fingerprint: " + fingerprint)
		}

		return nil
	}
}

// 压缩为zip格式
// source为要压缩的文件或文件夹, 绝对路径和相对路径都可以
// target是目标文件
// filter是过滤正则(Golang 的 包 path.Match)
func Zipit(source, target, filter string) error {
	var err error
	if isAbs := filepath.IsAbs(source); !isAbs {
		source, err = filepath.Abs(source) // 将传入路径直接转化为绝对路径
		if err != nil {
			return err
		}
	}
	//创建zip包文件
	zipfile, err := os.Create(target)
	if err != nil {
		return err
	}

	defer func() {
		if err := zipfile.Close(); err != nil {
			log.Fatal("❌ Failed to File close error: %s, file: %s", err.Error(), zipfile.Name())
		}
	}()

	//创建zip.Writer
	zw := zip.NewWriter(zipfile)

	defer func() {
		if err := zw.Close(); err != nil {
			log.Fatal("❌ Failed to zipwriter close error: %s", err.Error())
		}
	}()

	info, err := os.Stat(source)
	if err != nil {
		return err
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}
	excludeArr := strings.Split(filter, ",")

	err = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return err
		}

		//将遍历到的路径与pattern进行匹配
		ism, err := filepath.Match(filter, info.Name())

		if err != nil {
			return err
		}
		//如果匹配就忽略
		if ism {
			return nil
		}
		for _, v := range excludeArr {
			old_v := v
			isAbs := filepath.IsAbs(v)
			if !isAbs {
				v, err = filepath.Abs(v) // 将传入路径直接转化为绝对路径
				if err != nil {
					return err
				}
			}
			if v == path {
				return nil
			}

			// fmt.Println(strings.HasSuffix(old_v, "/") == true, strings.HasPrefix(path, v))
			// fmt.Println(path, v)
			//判断排除目录
			if strings.HasSuffix(old_v, "/") == true && strings.HasPrefix(path, v+"/") {
				return nil
			}

		}

		//创建文件头
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}
		//写入文件头信息
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}
		//写入文件内容
		file, err := os.Open(path)
		if err != nil {
			return err
		}

		defer func() {
			if err := file.Close(); err != nil {
				log.Fatal("❌ Failed to File close error: %s, file: %s", err.Error(), zipfile.Name())
			}
		}()
		_, err = io.Copy(writer, file)

		return err
	})

	if err != nil {
		return err
	}

	return nil
}

// zip远程解压
func SSHUnZip(sshClient *ssh.Client, remote string) error {
	session, err := sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stderr := &bytes.Buffer{}
	session.Stderr = stderr
	stdout := &bytes.Buffer{}
	session.Stdout = stdout
	writer, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer writer.Close()
	err = session.Start("unzip -o " + remote + " -d " + filepath.ToSlash(filepath.Dir(remote)))

	if err != nil {
		return err
	}

	session.Wait()
	fmt.Println(remote)

	//NOTE: Process exited with status 1 is not an error, it just how scp work. (waiting for the next control message and we send EOF)
	return nil
}
