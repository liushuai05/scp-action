package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
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

	// 	os.Setenv("KEY", `-----BEGIN OPENSSH PRIVATE KEY-----
	// b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
	// NhAAAAAwEAAQAAAYEA6KIlO9HmYBwXcUKlLPedVkWp17CwwDV8Jio7oEa3XzOl6NURBgzW
	// F8zvhbP/Xt7Gn0J+EXhku8QFO0MdbW2+NA2Nfk3jNGc5DQo/1eeJxkf8wqxAL3r6S8smRh
	// Q6/oqJ/UKSqI8T1q+asvQUF1al9KAZ3CvTshQEZTBL6RBbGSaRzBNLXizfuTeFkJ4mUdF7
	// UKN+8sA+7ZyzrtUjFUxMvDQOV+SclPq4OL96/hggFfjp2SX8p0d233VXVLKDVsNodHgCni
	// pl597XUTR7My7KokxSLZj7/VBPTECEK7t+TtOOfspECIhe1j90WkUpHCAd3zn2MyXQYYb5
	// 5+NN+zN3SErA2nnR3YOIKJJFtjAQIVTtPchFx5ZpwebLVyOw4UTPoCTNlqat74eebYBk7w
	// P1SmbSWnMLWFDuuR9nfh8DmGerSKMZTVGj75sFyF0LFVroULlfjDxSfCJMzDoqLNeXM4Cd
	// m8lEd556b59xTjJ3e2fJX7yKo06zzHl66wfnyWMnAAAFiHtEaIp7RGiKAAAAB3NzaC1yc2
	// EAAAGBAOiiJTvR5mAcF3FCpSz3nVZFqdewsMA1fCYqO6BGt18zpejVEQYM1hfM74Wz/17e
	// xp9CfhF4ZLvEBTtDHW1tvjQNjX5N4zRnOQ0KP9XnicZH/MKsQC96+kvLJkYUOv6Kif1Ckq
	// iPE9avmrL0FBdWpfSgGdwr07IUBGUwS+kQWxkmkcwTS14s37k3hZCeJlHRe1CjfvLAPu2c
	// s67VIxVMTLw0DlfknJT6uDi/ev4YIBX46dkl/KdHdt91V1Syg1bDaHR4Ap4qZefe11E0ez
	// MuyqJMUi2Y+/1QT0xAhCu7fk7Tjn7KRAiIXtY/dFpFKRwgHd859jMl0GGG+efjTfszd0hK
	// wNp50d2DiCiSRbYwECFU7T3IRceWacHmy1cjsOFEz6AkzZamre+Hnm2AZO8D9Upm0lpzC1
	// hQ7rkfZ34fA5hnq0ijGU1Ro++bBchdCxVa6FC5X4w8UnwiTMw6KizXlzOAnZvJRHeeem+f
	// cU4yd3tnyV+8iqNOs8x5eusH58ljJwAAAAMBAAEAAAGAARcNhPUw/u/oF/lSauHj01TbLj
	// TTWcHUDfE4TiGyANfUenmBARH639LPIp5E8h9RBEnuXABshGlimXNIQ7sgyQ095huM4gcv
	// NP3QtbuDmqruocS6tZ/z377Dw6kBlKrjqiS3Hwla1UaszEnoKgHHRcnDTV1HctQeqcQUFP
	// QqO5DggdCo4Fd8U7yhk/e0uopj8CPCYgyOrknhwfOSGvXSqml35hxSDH7EZARtrKlaUXS7
	// cX0jfD86mvInC3qq82aZnr0/977SMWbuyA07lfjFdkETExJRPyzqk1Yt6/OLQ/9twlpc6T
	// 0852TmouLIui3nIvqErrvB1TTv7aycLnw+dUu/dnksjJeNWMYqMTOuaLR09TQawtUvot6H
	// YKIXVxV5iLcPbScf6YxuCEXhnNtGSYosDeWO6pbopv998nvVjlO80etkRulglNmYGEsSS8
	// QaWq2H2588Utcr0MMCamNqXxCwen8zZB3KpD4R9C0IOZIXCoYnI+b0u/oXFy/qsqyZAAAA
	// wGiuJ2g5DKth/h7HFQWzeYHPiWugRQHRKPql45Sg274DNlvsm0FVH2PFveI9gOOUvOb+XJ
	// kDhE+dAfazn9X8/XfsKc62LFwStHQF6y5GKeJLrlu7P39fAiwa70fQe0qIV4pQtYkOrkrI
	// 1F1p/qFvcgGvexgs9B0djIJMs6fqcSZquw2hE5DtPICztdPW4qrnkcECz3yrVtKO/b+LsR
	// tEY93FBhCWBMmI+SCWDQlBGA7IWfFyT+PN8PvtsXGrMdi5ggAAAMEA8sZCLF7MvqKa95fr
	// orGn8GajeNY5dB2l4yiWUlG68yBIlRFvhHDjBpZr4q1KMYeAeEojcMmtM+waEOHDXPSEDr
	// BnCjaMiDfmiLQmwuzRYsXVfl23H65st02k1ug4xbzXqYiWY3xIbd7wPYCag28+FovsCLnT
	// /jy5ee1pRhS3jdIpcr1d9rimwBYfAvDMclzsWEHjUNKLXpC83qxUKedo/2t3CwP/BUJPqS
	// 2GPjYr7ZfA6YAbvOjqs1aFMycu8g/JAAAAwQD1TnWSIhqROuHeV9fTgTnCiiWg1Rn1HlQU
	// UQHR5mrNROP1b4cJHdx27dmLT7MqAWsCk4Qb/NdrTBDjJSQzayQo62Mr56EeGgwi6XKXmd
	// iDOgPASWytztgK8bX2miMuKho055TDKkOwRM88ezhrDWx1H8ezWsgWcx6IZX8gJwe1oVme
	// GbLFbqJ8KYfE1X+AaHZU60JiK/j4bna2pAvgrWw7NmHN6+r0YjF4tOEdZvYrjYgz7X61vn
	// AX7rCbJ9Dzs28AAAAQNzQ3MzU3NzY2QHFxLmNvbQECAw==
	// -----END OPENSSH PRIVATE KEY-----`)

	fmt.Println("name: ", os.Getenv("KEY"))
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

		cmd := exec.Command("zip", "-r", dst, src)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Env = append(os.Environ(),
			"FOO=duplicate_value", // 重复被忽略
			"FOO=actual_value",    // 实际被使用
		)
		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Out: %q\n", out.String())

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
		fmt.Println(key)
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
	err = session.Start("unzip " + remote + " -d -o " + filepath.ToSlash(filepath.Dir(remote)))

	if err != nil {
		return err
	}

	session.Wait()
	fmt.Println(remote)

	//NOTE: Process exited with status 1 is not an error, it just how scp work. (waiting for the next control message and we send EOF)
	return nil
}
