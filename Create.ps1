Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Create New AD User"
$form.Size = New-Object System.Drawing.Size(400, 650) # Adjusted size for additional field
$form.StartPosition = "CenterScreen"

# Labels and TextBoxes
$labels = @("First Name", "Last Name", "Title", "Start Date", "Phone Number", "Manager", "Country", "City", "Email Address", "Password")
$textBoxes = @()
$yPos = 20

foreach ($label in $labels) {
    $labelControl = New-Object System.Windows.Forms.Label
    $labelControl.Text = $label
    $labelControl.Location = New-Object System.Drawing.Point(10, $yPos)
    $labelControl.AutoSize = $true
    $form.Controls.Add($labelControl)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(120, $yPos)
    $textBox.Size = New-Object System.Drawing.Size(250, 20)

    # Make the password field hide input
    if ($label -eq "Password") {
        $textBox.PasswordChar = '*'
    }

    $form.Controls.Add($textBox)
    $textBoxes += $textBox

    $yPos += 30
}

# AD Groups Dropdown
$labelADGroup = New-Object System.Windows.Forms.Label
$labelADGroup.Text = "AD Group"
$labelADGroup.Location = New-Object System.Drawing.Point(10, $yPos)
$labelADGroup.AutoSize = $true
$form.Controls.Add($labelADGroup)

$comboBoxADGroup = New-Object System.Windows.Forms.ComboBox
$comboBoxADGroup.Location = New-Object System.Drawing.Point(120, $yPos)
$comboBoxADGroup.Size = New-Object System.Drawing.Size(250, 20)
$form.Controls.Add($comboBoxADGroup)

# Populate AD Groups
$adGroups = Get-ADGroup -Filter * | Select-Object -ExpandProperty Name
foreach ($group in $adGroups) {
    $comboBoxADGroup.Items.Add($group)
}

$yPos += 30

# Azure AD Delta Sync Checkbox
$checkBoxAzureSync = New-Object System.Windows.Forms.CheckBox
$checkBoxAzureSync.Text = "Azure AD Delta Sync"
$checkBoxAzureSync.Location = New-Object System.Drawing.Point(10, $yPos)
$checkBoxAzureSync.AutoSize = $true
$form.Controls.Add($checkBoxAzureSync)

$yPos += 30

# Create Button
$buttonCreate = New-Object System.Windows.Forms.Button
$buttonCreate.Text = "Create User"
$buttonCreate.Location = New-Object System.Drawing.Point(150, $yPos)
$buttonCreate.Size = New-Object System.Drawing.Size(100, 30)
$buttonCreate.Add_Click({
    $firstName = $textBoxes[0].Text
    $lastName = $textBoxes[1].Text
    $title = $textBoxes[2].Text
    $startDate = $textBoxes[3].Text
    $phoneNumber = $textBoxes[4].Text
    $manager = $textBoxes[5].Text
    $country = $textBoxes[6].Text
    $city = $textBoxes[7].Text
    $emailAddress = $textBoxes[8].Text
    $password = $textBoxes[9].Text
    $adGroup = $comboBoxADGroup.SelectedItem
    $azureSync = $checkBoxAzureSync.Checked

    # Validate password (minimum length)
    if ($password.Length -lt 8) {
        [System.Windows.Forms.MessageBox]::Show("Password must be at least 8 characters long.", "Error")
        return
    }

    # Create the user in AD
    try {
        $newUserParams = @{
            GivenName = $firstName
            Surname = $lastName
            Name = "$firstName $lastName"
            SamAccountName = "$firstName.$lastName"
            UserPrincipalName = "$firstName.$lastName@yourdomain.com"
            EmailAddress = $emailAddress
            Title = $title
            OfficePhone = $phoneNumber
            Manager = $manager
            City = $city
            Country = $country
            AccountPassword = ConvertTo-SecureString $password -AsPlainText -Force
            Enabled = $true
        }

        New-ADUser @newUserParams

        # Add user to selected AD group
        if ($adGroup) {
            Add-ADGroupMember -Identity $adGroup -Members "$firstName.$lastName"
        }

        # Azure AD Delta Sync (if checked)
        if ($azureSync) {
            # Placeholder for Azure AD Delta Sync logic
            Write-Host "Azure AD Delta Sync would be triggered here."
        }

        [System.Windows.Forms.MessageBox]::Show("User created successfully!", "Success")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error creating user: $_", "Error")
    }
})
$form.Controls.Add($buttonCreate)

# Show the form
$form.ShowDialog()