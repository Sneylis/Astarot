package main

import (
	core "Astarot/core/Analyze"
	"Astarot/recon/passive"
	"fmt"
)

func main() {
	//banner
	var domain string
	banner := `

	▄▄▄        ██████ ▄▄▄█████▓ ▄▄▄       ██▀███   ▒█████  ▄▄▄█████▓
	▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓  ██▒ ▓▒
	▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▒ ▓██░ ▒░
	░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░░ ▓██▓ ░
	▓█   ▓██▒▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░  ▒██▒ ░
	▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░   ▒ ░░
	▒   ▒▒ ░░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░     ░
	░   ▒   ░  ░  ░    ░        ░   ▒     ░░   ░ ░ ░ ░ ▒    ░
		░  ░      ░                 ░  ░   ░         ░ ░

			Recon tool - Astarot v1.0`
	fmt.Println(banner)
	fmt.Printf("Domain: -> ")
	fmt.Scanln(&domain)
	passive.PassiveMain(domain)
	core.WappalyzerMain()

}
