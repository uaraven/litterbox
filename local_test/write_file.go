package main

import "os"

func main() {
	os.WriteFile("example.txt", []byte("Hello, World!"), 0644)
}