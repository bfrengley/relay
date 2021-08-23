package main

import (
	"flag"
	"log"
	"os"

	"github.com/bfrengley/relay"
)

func main() {
	var serverFlag = flag.String("server", "http://localhost:8080", "URL of the remote server")
	var downloadFlag = flag.String("download", "", "Id of the file to download")
	var uploadFlag = flag.String("upload", "", "Path to the file to upload")

	flag.Parse()

	if serverFlag == nil ||
		*serverFlag == "" ||
		(downloadFlag != nil && uploadFlag != nil && *downloadFlag != "" && *uploadFlag != "") ||
		(*downloadFlag == "" && *uploadFlag == "") {
		flag.Usage()
		os.Exit(1)
	}

	rc := relay.NewClient(*serverFlag)
	if *uploadFlag != "" {
		if err := rc.UploadFile(*uploadFlag, "thisisatestpassword"); err != nil {
			log.Fatalln("ERR:", err)
		}
	} else if *downloadFlag != "" {
		data, err := rc.DownloadFile(*downloadFlag, "thisisatestpassword")
		if err != nil {
			log.Fatalln("ERR:", err)
		}
		if data != nil {
			if _, err = os.Stdout.Write(data); err != nil {
				log.Fatalln("ERR:", err)
			}
		}
	}
}
