package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/saschazar21/go-oidc-provider/cli"
	"github.com/saschazar21/go-oidc-provider/models"
	"github.com/saschazar21/go-oidc-provider/utils"
)

func readPrimary(reader *bufio.Reader, user *models.User) {
	email, err := cli.ReadLine(reader, "E-Mail Address")
	if err != nil {
		fmt.Printf("Error reading E-Mail Address: %v\n", err)
		os.Exit(1)
	}
	if email == "" {
		fmt.Println("E-Mail Address is required, exiting...")
		os.Exit(1)
	}

	encryptedEmail := utils.EncryptedString(email)
	user.Email = &encryptedEmail
}

func readSecondary(reader *bufio.Reader, user *models.User) {
	givenName, err := cli.ReadLine(reader, "First Name")
	if err != nil {
		fmt.Printf("Error reading First Name: %v\n", err)
		os.Exit(1)
	}
	if givenName == "" {
		fmt.Println("First Name is required when opting for additional data, exiting...")
		os.Exit(1)
	}

	familyName, err := cli.ReadLine(reader, "Last Name")
	if err != nil {
		fmt.Printf("Error reading Last Name: %v\n", err)
		os.Exit(1)
	}
	if familyName == "" {
		fmt.Println("Last Name is required when opting for additional data, exiting...")
		os.Exit(1)
	}

	encryptedGivenName := utils.EncryptedString(givenName)
	encryptedFamilyName := utils.EncryptedString(familyName)

	user.GivenName = &encryptedGivenName
	user.FamilyName = &encryptedFamilyName

	middleName, err := cli.ReadLine(reader, "Middle Name (optional)")
	if err != nil {
		fmt.Printf("Error reading Middle Name: %v\n", err)
		os.Exit(1)
	}
	if middleName != "" {
		encryptedMiddleName := utils.EncryptedString(middleName)
		user.MiddleName = &encryptedMiddleName
	}
}

func readTertiary(reader *bufio.Reader, user *models.User) {
	nickname, err := cli.ReadLine(reader, "Nickname (optional)")
	if err != nil {
		fmt.Printf("Error reading Nickname: %v\n", err)
		os.Exit(1)
	}
	if nickname != "" {
		user.Nickname = &nickname
	}

	pictureURL, err := cli.ReadLine(reader, "Picture URL (optional)")
	if err != nil {
		fmt.Printf("Error reading Picture URL: %v\n", err)
		os.Exit(1)
	}
	if pictureURL != "" {
		encryptedPictureURL := utils.EncryptedString(pictureURL)
		user.Picture = &encryptedPictureURL
	}

	preferredUsername, err := cli.ReadLine(reader, "Preferred Username (optional)")
	if err != nil {
		fmt.Printf("Error reading Preferred Username: %v\n", err)
		os.Exit(1)
	}
	if preferredUsername != "" {
		user.PreferredUsername = &preferredUsername
	}

	birthdate, err := cli.ReadLine(reader, "Birthdate (YYYY-MM-DD) (optional)")
	if err != nil {
		fmt.Printf("Error reading Birthdate: %v\n", err)
		os.Exit(1)
	}
	if birthdate != "" {
		b, err := time.Parse("2006-01-02", birthdate)
		if err != nil {
			fmt.Printf("Error parsing Birthdate: %v\n", err)
			os.Exit(1)
		}
		encryptedBirthdate := utils.EncryptedDate{
			Time: b,
		}
		user.Birthdate = &encryptedBirthdate
	}

	gender, err := cli.ReadLine(reader, "Gender (optional)", "male", "female", "other")
	if err != nil {
		fmt.Printf("Error reading Gender: %v\n", err)
		os.Exit(1)
	}
	if gender != "" {
		encryptedGender := utils.EncryptedString(gender)
		user.Gender = &encryptedGender
	}

	website, err := cli.ReadLine(reader, "Website URL (optional)")
	if err != nil {
		fmt.Printf("Error reading Website URL: %v\n", err)
		os.Exit(1)
	}
	if website != "" {
		encryptedWebsite := utils.EncryptedString(website)
		user.Website = &encryptedWebsite
	}

	profile, err := cli.ReadLine(reader, "Profile URL (optional)")
	if err != nil {
		fmt.Printf("Error reading Profile URL: %v\n", err)
		os.Exit(1)
	}
	if profile != "" {
		encryptedProfile := utils.EncryptedString(profile)
		user.Profile = &encryptedProfile
	}

	locale, err := cli.ReadLine(reader, "Locale (optional)")
	if err != nil {
		fmt.Printf("Error reading Locale: %v\n", err)
		os.Exit(1)
	}
	if locale != "" {
		user.Locale = &locale
	}

	zoneinfo, err := cli.ReadLine(reader, "Timezone (optional)")
	if err != nil {
		fmt.Printf("Error reading Timezone: %v\n", err)
		os.Exit(1)
	}
	if zoneinfo != "" {
		user.Zoneinfo = &zoneinfo
	}
}

func readPhoneNumber(reader *bufio.Reader, user *models.User) {
	phoneNumber, err := cli.ReadLine(reader, "Phone Number (optional)")
	if err != nil {
		fmt.Printf("Error reading Phone Number: %v\n", err)
		os.Exit(1)
	}
	if phoneNumber != "" {
		encryptedPhoneNumber := utils.EncryptedString(phoneNumber)
		user.PhoneNumber = &encryptedPhoneNumber
	}
}

func readAddress(reader *bufio.Reader, user *models.User) {
	var address models.Address

	streetAddress, err := cli.ReadLine(reader, "Street Address (optional)")
	if err != nil {
		fmt.Printf("Error reading Street Address: %v\n", err)
		os.Exit(1)
	}
	if streetAddress != "" {
		encryptedStreetAddress := utils.EncryptedString(streetAddress)
		address.StreetAddress = &encryptedStreetAddress
	}

	locality, err := cli.ReadLine(reader, "Locality (optional)")
	if err != nil {
		fmt.Printf("Error reading Locality: %v\n", err)
		os.Exit(1)
	}
	if locality != "" {
		encryptedLocality := utils.EncryptedString(locality)
		address.Locality = &encryptedLocality
	}

	region, err := cli.ReadLine(reader, "Region (optional)")
	if err != nil {
		fmt.Printf("Error reading Region: %v\n", err)
		os.Exit(1)
	}
	if region != "" {
		encryptedRegion := utils.EncryptedString(region)
		address.Region = &encryptedRegion
	}

	postalCode, err := cli.ReadLine(reader, "Postal Code (optional)")
	if err != nil {
		fmt.Printf("Error reading Postal Code: %v\n", err)
		os.Exit(1)
	}
	if postalCode != "" {
		encryptedPostalCode := utils.EncryptedString(postalCode)
		address.PostalCode = &encryptedPostalCode
	}

	country, err := cli.ReadLine(reader, "Country (optional)")
	if err != nil {
		fmt.Printf("Error reading Country: %v\n", err)
		os.Exit(1)
	}
	if country != "" {
		address.Country = &country
	}

	user.Address = &address
}
