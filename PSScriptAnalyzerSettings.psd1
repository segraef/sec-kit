@{
    # SecKit is a CLI tool, not a reusable PowerShell module. Suppress rules
    # that only matter for cmdlet/module authors. Errors and security rules
    # still fire normally.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',                       # interactive CLI prints to host on purpose
        'PSUseShouldProcessForStateChangingFunctions', # enforce.ps1 has its own -Apply / dry-run flag
        'PSUseSingularNouns',                          # Get-Reminders, Find-Clients etc. are plural by design
        'PSAvoidUsingPositionalParameters',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSReviewUnusedParameter'                      # ValueFromRemainingArguments fan-out
    )
}
