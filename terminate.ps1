<#
MIT License for Non-Profit Use

Copyright (c) 2025 Five-10 Solutions

Permission is hereby granted, free of charge, to any person obtaining a copy
of this script and associated documentation files (the "script"), to deal
in the script without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the script, and to permit persons to whom the script is
furnished to do so, subject to the following conditions:

1. The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the script.
2. The script is provided for non-profit use only. Any commercial use, including
   but not limited to selling the script, incorporating it into a commercial
   product, or using it to provide paid services, requires a separate commercial
   license.

For commercial licensing inquiries, please contact:
Infosec_Viking {AKA Max S.}
Max@five-10.com

THE script IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE script OR THE USE OR OTHER DEALINGS IN THE
script.

I am not a software dev - I am an idiot that likes powershell, this shit may break things
don't be dumb, and be aware of what these scripts do.  If you don't understand powershell,
you have no business 
#>
# Import required modules
Import-Module ActiveDirectory

# Create Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Function to create the termination form
function Create-TerminationForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Active Directory User Termination"
    $form.Size = New-Object System.Drawing.Size(400, 500)

    # Create Labels and Textboxes for input fields
    $labels = @{
        "Username"       = "Username"
        "Description"    = "Description (e.g., Termination Date)"
    }

    $yPos = 20
    $controls = @{}

    # Add search field
    foreach ($field in $labels.Keys) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $labels[$field]
        $label.Location = New-Object System.Drawing.Point(10, $yPos)
        $label.Size = New-Object System.Drawing.Size(100, 20)

        $textbox = New-Object System.Windows.Forms.TextBox
        $textbox.Name = $field
        $textbox.Location = New-Object System.Drawing.Point(120, $yPos)
        $textbox.Size = New-Object System.Drawing.Size(200, 20)
        
        $form.Controls.Add($label)
        $form.Controls.Add($textbox)

        $controls[$field] = $textbox
        $yPos += 30
    }

    # Create Checkbox for moving to a different AD group
    $chkMoveGroup = New-Object System.Windows.Forms.CheckBox
    $chkMoveGroup.Text = "Move to Different AD Group"
    $chkMoveGroup.Location = New-Object System.Drawing.Point(120, $yPos)
    $chkMoveGroup.Size = New-Object System.Drawing.Size(200, 20)
    $chkMoveGroup.Checked = $false
    $form.Controls.Add($chkMoveGroup)
    $controls["MoveGroup"] = $chkMoveGroup

    # Create dropdown for AD groups
    $yPos += 30
    $labelGroup = New-Object System.Windows.Forms.Label
    $labelGroup.Text = "Select AD Group"
    $labelGroup.Location = New-Object System.Drawing.Point(10, $yPos)
    $labelGroup.Size = New-Object System.Drawing.Size(100, 20)
    $form.Controls.Add($labelGroup)

    $comboboxADGroups = New-Object System.Windows.Forms.ComboBox
    $comboboxADGroups.Location = New-Object System.Drawing.Point(120, $yPos)
    $comboboxADGroups.Size = New-Object System.Drawing.Size(200, 20)
    $comboboxADGroups.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $form.Controls.Add($comboboxADGroups)
    $controls["ADGroups"] = $comboboxADGroups

    # Populate AD Groups dropdown
    $adGroups = Get-ADGroup -Filter * | Select-Object -ExpandProperty Name
    $comboboxADGroups.Items.AddRange($adGroups)

    # Create option to disable user
    $yPos += 30
    $chkDisableUser = New-Object System.Windows.Forms.CheckBox
    $chkDisableUser.Text = "Disable User"
    $chkDisableUser.Location = New-Object System.Drawing.Point(120, $yPos)
    $chkDisableUser.Size = New-Object System.Drawing.Size(200, 20)
    $form.Controls.Add($chkDisableUser)
    $controls["DisableUser"] = $chkDisableUser

    # Create option to reset password
    $yPos += 30
    $labelPassword = New-Object System.Windows.Forms.Label
    $labelPassword.Text = "New Password"
    $labelPassword.Location = New-Object System.Drawing.Point(10, $yPos)
    $labelPassword.Size = New-Object System.Drawing.Size(100, 20)

    $textboxPassword = New-Object System.Windows.Forms.TextBox
    $textboxPassword.Name = "NewPassword"
    $textboxPassword.Location = New-Object System.Drawing.Point(120, $yPos)
    $textboxPassword.Size = New-Object System.Drawing.Size(200, 20)
    $textboxPassword.PasswordChar = '*'
    $form.Controls.Add($labelPassword)
    $form.Controls.Add($textboxPassword)
    $controls["NewPassword"] = $textboxPassword

    # Create Terminate Button
    $btnTerminate = New-Object System.Windows.Forms.Button
    $btnTerminate.Text = "Terminate"
    $btnTerminate.Location = New-Object System.Drawing.Point(120, $yPos + 30)
    $btnTerminate.Size = New-Object System.Drawing.Size(200, 30)
    $btnTerminate.Add_Click({
        Terminate-User -controls $controls
    })
    $form.Controls.Add($btnTerminate)

    # Display the form
    $form.ShowDialog()
}

# Function to terminate AD User
function Terminate-User {
    param (
        $controls
    )

    $userName = $controls["Username"].Text
    $user = Get-ADUser -Filter {SamAccountName -eq $userName}

    if ($null -eq $user) {
        [System.Windows.Forms.MessageBox]::Show("User not found", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if ($controls["MoveGroup"].Checked) {
        $newGroup = $controls["ADGroups"].SelectedItem
        Add-ADGroupMember -Identity $newGroup -Members $user
    }

    if ($controls["DisableUser"].Checked) {
        Disable-ADAccount -Identity $user
    }

    if ($controls["NewPassword"].Text) {
        $newPassword = ConvertTo-SecureString $controls["NewPassword"].Text -AsPlainText -Force
        Set-ADAccountPassword -Identity $user -NewPassword $newPassword
    }

    if ($controls["Description"].Text) {
        Set-ADUser -Identity $user -Description $controls["Description"].Text
    }

    [System.Windows.Forms.MessageBox]::Show("User terminated successfully", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

# Initiate the form creation
Create-TerminationForm
