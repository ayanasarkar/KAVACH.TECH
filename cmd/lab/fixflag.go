package main

import "os"

// labFixed reports whether the demo "fix" flag file exists. While it does, the weak site stops serving its exposed
// files (/.env and /.git/HEAD), as if the developer had deployed a fix, so a retest can show a real REMEDIATED.
// The file is lab-fixed.flag in the lab's working directory, or the path in LAB_FIXED_FLAG. With no file the lab
// behaves exactly as before.
func labFixed() bool {
	p := os.Getenv("LAB_FIXED_FLAG")
	if p == "" {
		p = "lab-fixed.flag"
	}
	_, err := os.Stat(p)
	return err == nil
}
