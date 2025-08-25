# Password Strength Analyzer & Wordlist Generator

## Description

A Python tool to analyze password strength using `zxcvbn`, generate custom wordlists from user inputs, and export them for security testing or password auditing. Includes CLI support and optional GUI interface.

## Features

* Analyze password strength with entropy calculations.
* Generate custom wordlists using user inputs (name, date, pet, extra keywords).
* Include common patterns like leetspeak and appended years.
* Export wordlists in `.txt` format suitable for password cracking tools.
* CLI interface and optional GUI with `tkinter`.

## Installation

1. Clone the repository or download the ZIP file.
2. Install required Python libraries:

```bash
pip install zxcvbn nltk
```

## Usage

### CLI Example

```bash
python pwtool.py --password "Winter2025!" --name "Lekhana" --pet "Bruno" --date "2001-06-15" --extra "cyber" --profile balanced --outfile out.txt
```

* `--password` : Password to analyze.
* `--name` : User's name.
* `--pet` : Pet's name.
* `--date` : Important date (YYYY-MM-DD).
* `--extra` : Extra keywords.
* `--profile` : Wordlist profile (`fast`, `balanced`, `comprehensive`).
* `--outfile` : Path to save generated wordlist.

### Output

* Password analysis: strength score, entropy, estimated crack times, feedback.
* Wordlist generation: candidate passwords saved in the specified `.txt` file.

## Optional GUI

* Launch GUI by running the script without CLI arguments (if implemented).
* Enter password and user details in the interface to generate analysis and wordlist.

## Contributing

* Feel free to fork the repository and submit pull requests.
* Suggestions for new features and improvements are welcome.

## License

* MIT License
