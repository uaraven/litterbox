package main

import (
	"fmt"
	"os"
)

func main() {
	err := os.WriteFile("example.txt", []byte("Hello, World!"), 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
	}
}