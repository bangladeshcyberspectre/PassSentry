# PassSentry

A small command-line tool that checks whether a password has appeared in known data breaches, without ever sending the password anywhere.

It uses the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) *Pwned Passwords* range API with **k-anonymity**: only the first 5 characters of the password's SHA-1 hash are sent. The rest of the comparison happens locally on your machine.

## Features

- Hidden password prompt (nothing shown or stored in shell history)
- Batch mode: check a whole file of passwords
- Basic local strength tips
- Script-friendly exit codes
- Zero dependencies, standard library only

## Requirements

- Python 3.8 or newer
- Internet connection

## Usage

Check a single password (input is hidden):

```bash
python passsentry.py
```

Check many passwords from a file, one per line:

```bash
python passsentry.py --file passwords.txt
```

Example output:

```
PWNED: this password appears 10,434,004 times in known breaches.
Don't use it anywhere. Pick a new one, ideally a long passphrase.
Tips: use at least 12 characters (longer is better); mix upper and lower case; add a digit; add a symbol.
```

In batch mode, passwords are masked in the output (only the first character is shown).

### Exit codes

| Code | Meaning                        |
|------|--------------------------------|
| 0    | Not found in known breaches    |
| 1    | Found in known breaches        |
| 2    | Error (network, file, no input)|

This makes it easy to use in scripts:

```bash
python passsentry.py --file passwords.txt || echo "Some passwords are compromised"
```

## How it works

1. Your password is hashed locally with SHA-1.
2. The first 5 hex characters of the hash (the prefix) are sent to the API.
3. The API returns every hash suffix that shares that prefix, along with breach counts.
4. The tool looks for your suffix in that list locally.

The request also uses the `Add-Padding` header so response sizes don't leak information.

## Privacy and safety notes

- Your full password and full hash never leave your machine.
- "Not found" does **not** mean "strong". A short or guessable password can be unbreached and still weak. Prefer long, unique passphrases and a password manager.
- Don't paste real passwords into files you plan to commit or share. Delete batch files after use.

## Limitations

- Checks passwords only, not email addresses (email breach lookups require a paid HIBP API key).
- Strength tips are rough hints, not a real strength estimate.

## Contributing

Issues and pull requests are welcome. Please keep the tool dependency-free and keep the k-anonymity guarantee intact.

## License

Released under the [MIT License](LICENSE).

## Credits

Made by **Ochena Gamer**.

Breach data provided by [Have I Been Pwned](https://haveibeenpwned.com/) by Troy Hunt.
