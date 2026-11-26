package main

import "example.com/demo/pkg"

func main() {
	pkg.Read("config.txt")
	pkg.Touch()
	pkg.Client()
}
