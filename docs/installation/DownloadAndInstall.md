# Download and Python Install

## Downloading the Latest Release
To download ScubaGoggles:

1. Click [here](https://github.com/cisagov/ScubaGoggles/releases) to see the latest release.
2. Click scubagoggles-[latest-version].zip to download the release.
3. Extract the folder in the zip file.

## Installing Python Dependencies
Minimum required Python version to run the tool is `3.7.16`.

### Installing in a Virtual Environment
The following commands are used to set up a python virtual environment (venv) to install the needed python dependencies.
Inside the release or repo folder, open up a terminal and run the following commands based on your OS.

#### Windows
```
pip3 install virtualenv
python -m venv .venv
.venv\Scripts\activate
```

#### macOS
```
pip3 install virtualenv
virtualenv -p python3 .venv
source .venv/bin/activate
```

Users can run the tool via the `scuba.py` script as a developer or by installing the `scubagoggles` package in a python venv.
Choose either of these next steps to install the needed python dependencies in the `venv`.

#### Installing dependencies for running scubagoggles directly
In the root directory of the release/repo, install the `scubagoggles` package and dependencies with the following command.
```
python3 -m pip install .
```

#### Installing dependencies for running via scuba.py script
In the root directory of the release/repo, install the the required dependencies with the following command.
```
pip3 install -r requirements.txt
```

> [!IMPORTANT]
> Users will need to rerun the `activate` script from the OS specific directions above in each new terminal session to reactivate the `venv` containing the dependencies.

## Navigation
- Continue to [Download the OPA executable](/docs/installation/OPA.md)
- Return to [Documentation Home](/README.md)
