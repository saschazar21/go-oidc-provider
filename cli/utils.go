package cli

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/saschazar21/go-oidc-provider/utils"
)

func ReadLine(reader *bufio.Reader, prompt string, allowedValues ...string) (string, error) {
	options := strings.Join(allowedValues, ", ")
	if len(allowedValues) > 0 {
		prompt = fmt.Sprintf("%s (%s)", prompt, options)
	}
	fmt.Printf("%s: ", prompt)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		input := strings.TrimSpace(line)

		if len(input) == 0 {
			return "", nil
		}

		if len(allowedValues) == 0 {
			return input, nil
		}

		segments := strings.Split(input, ",")
		for _, s := range segments {
			if !utils.ContainsValue(allowedValues, strings.TrimSpace(s)) {
				err = fmt.Errorf("value not supported: %s", s)
				break
			}
		}

		if err == nil {
			return input, nil
		} else {
			fmt.Printf("%v\n", err)
		}

		fmt.Printf("Invalid input. Allowed values are: %s\n", strings.Join(allowedValues, ", "))
	}
}

func ReadYN(reader *bufio.Reader, prompt string) (bool, error) {
	for {
		input, err := ReadLine(reader, prompt+" (y/n)")
		if err != nil {
			return false, err
		}
		input = strings.ToLower(input)
		switch input {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Println("Please enter 'y(es)' or 'n(o)'.")
		}
	}
}
