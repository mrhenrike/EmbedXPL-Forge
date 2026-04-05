# POC Seeker

POC Seeker is an innovative tool designed to streamline the process of finding and analyzing Proof of Concept (PoC) codes for known Common Vulnerabilities and Exposures (CVEs).

![POC Seeker](https://github.com/0xyassine/logo/blob/main/poc-seeker.png?raw=true)

## Features

- **CVE Search**: Quickly search for CVEs to find associated PoC exploits.
- **Database Integration**: Access a comprehensive database of CVEs with their detailed descriptions and associated PoCs.
- **User-Friendly Interface**: Designed with ease of use in mind, POC Seeker can be used by professionals and beginners alike.
- **Searching into 5 sources**: GitHub, Sploitus, Exploit-DB, Vulnerability-Lab, and Packet Storm Security, ensuring a comprehensive search with every query.
- **Saving results to a file**: Search results can be saved to a file making it easy to reference and analyze data at a later time.
- **Extension search**: Enhances search efficiency by directly targeting files that meet the specified criteria, reducing the volume of irrelevant data.

## Installation

POC Seeker can be installed using one line

```
sudo curl -s https://raw.githubusercontent.com/0xyassine/poc-seeker/master/poc-seeker.sh -o /usr/local/bin/poc-seeker && sudo chmod +x /usr/local/bin/poc-seeker
```

## Prerequisites

POC Seeker script is written in Bash and relies on several (usually pre-installed) external packages to function correctly. Ensure that your system has the following packages installed before using the script:

- **curl**
  - **Installation**: Most Linux distributions come with `curl` pre-installed. If you need to install it, you can typically do so using your package manager. For example, on Debian-based systems, use:
    ```bash
    sudo apt-get install curl
    ```

- **jq**
  - **Installation**: `jq` can be installed using your Linux distribution's package manager. For instance, on Debian-based systems, run:
    ```bash
    sudo apt-get install jq
    ```

- **searchsploit**
  - **Installation**: `searchsploit` is part of the Exploit Database repository. It can be installed on Debian-based systems by installing the `exploitdb` package or via a direct clone from its GitHub repository. For a direct installation, you can use:
    ```bash
    sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    ```
    Please refer to the [official Exploit-DB repository](https://github.com/offensive-security/exploitdb) for the most current installation instructions and options.


### Note:
The script is designed to be as compatible as possible with various Linux distributions. However, due to the diversity of Linux environments and configurations, some commands or installation methods might need slight adjustments. Always refer to your distribution's documentation for the most accurate and up-to-date information regarding package management and software installation.


## Command Line Options

POC Seeker supports a range of command-line options that enable users to customize their search for CVEs and associated PoCs. Below is a detailed explanation of each option:

- `-h` | `--help`
  - **Description**: Displays a helpful menu that includes all command-line options along with a brief description of what they do. This option is useful for getting a quick overview of the tool's capabilities.
  - **Example**: `./poc-seeker.sh --help`

- `-e` | `--extensions`
  - **Description**: Supply a list of file extensions separated by a comma and are optional; if not provided, the tool uses a default list. Make sure to select them correctly otherwise the script may not provide you non accurate results.
  - **Default Extensions**: .py,.rb,.pl,.sh,.ps1,.bat,.js,.php,.c,.cpp,.go,.lua,.rs,.swift
  - **Example**: `./poc-seeker.sh --query "CVE-2023-40028" -e ".sh,.py"`

- `-q` | `--query`
  - **Description**: Allows the user to provide a search query, which is mandatory for performing a search. The query can be a specific CVE identifier, a keyword, or any other term related to the vulnerabilities you're interested in.
  - **Example**: `./poc-seeker.sh --query "CVE-2023-40028"`

- `-s` | `--source`
  - **Description**: Enables specifying the sources from which to fetch the PoCs. The sources are separated by a comma and are optional; if not provided, the tool uses a default list of sources.
  - **Default Sources**: github, sploitus, exploit-db, vulnerability-lab, packetstormsecurity
  - **Example**: `./poc-seeker.sh --query "CVE-2023-40028" --source "github,exploit-db"`

- `-c` | `--check`
  - **Description**: Activates a precise checking mechanism to ensure that the CVE identifier is explicitly mentioned in the exploit, thereby improving the accuracy of the search results. This option is optional but recommended for more accurate filtering.
  - **Example**: `./poc-seeker.sh --check --query "CVE-2023-40028"`

- `-sl` | `--sploitus-limit`
  - **Description**: Sets a limit on the number of entries returned by Sploitus, allowing users to control the volume of data fetched. This is optional and can help in managing the output more effectively.
  - **Default Limit**: 10
  - **Example**: `./poc-seeker.sh --sploitus-limit 20 --query "CVE-2023-40028"`

- `-gl` | `--github-limit`
  - **Description**: Sets a limit on the number of entries returned by GitHub, allowing users to control the volume of data fetched. This is optional and can help in managing the output more effectively.
  - **Default Limit**: 10
  - **Example**: `./poc-seeker.sh --github-limit 20 --query "CVE-2023-40028"`

- `-o` | `--output`
  - **Description**: Saves the output of the search to a file. This option is beneficial for users who wish to review the results at a later time or keep a record of their searches.
  - **Example**: `./poc-seeker.sh --query "CVE-2023-40028" --output "search_results.txt"`

- `--github-access-token`
  - **Description**: Accepts a GitHub access token to increase the API request limit, enabling more extensive data fetching operations without hitting the rate limits. This is optional but can be very useful for heavy users.
  - **Example**: `./poc-seeker.sh --query "CVE-2023-40028" --github-access-token "your_token_here"`

- `--nvd-api-key`
  - **Description**: Provides an API key for the National Vulnerability Database (NVD) to increase the API request limit, similar to the GitHub access token. This option is optional and helps in conducting broader searches.
  - **Example**: `./poc-seeker.sh --query "CVE-2023-40028" --nvd-api-key "your_api_key_here"`

- `--disable-nvd`
  - **Description**: By default, the script will try to collect CVE information from the National Vulnerability Database (NVD) database. You can use this option to prevent the script from collecting this informations.
  - **Example**: `./poc-seeker.sh --query "CVE-2023-40028" --disable-nvd`

## Disclaimer

This repository and all associated files and resources are provided **for research purposes only**. The tools and information contained within this repository are intended to support security research and educational purposes. **This includes the use of web scraping technologies to gather data relevant to the research being conducted.**

Users must comply with all applicable laws and regulations regarding web scraping and data collection. The owner and contributors of this repository do not accept any responsibility for misuse of the information provided here or for any legal consequences or damages arising from such use.
