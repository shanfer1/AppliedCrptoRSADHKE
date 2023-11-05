# RSA Encryption/Decryption Project

This project is a C# console application implementing the RSA algorithm for encryption and decryption of messages using large prime numbers.

## Prerequisites

- .NET 6 SDK

## Installation

Follow these steps to set up the environment and run the application.

### Step 1: Install the .NET 6 SDK

Download and install the .NET 6 SDK from the official [.NET Download page](https://dotnet.microsoft.com/download/dotnet/6.0). Select the appropriate installer for your operating system and follow the installation prompts.

### Step 2: Verify Installation

Open a terminal or command prompt and execute the following command to verify that the .NET SDK has been installed correctly:

dotnet --version

## Step 3: Build the Project by Navigating to RSA Folder

Run the following command in the project directory to build the application:

cd rsa 

dotnet build


## Step 4 Running the Application

dotnet run <pe> <pc> <qe> <qc> <ee> <ec> <Ciphertext> <Plaintext>


example:

dotnet run 254 1223 251 1339 17 65535 66536047120374145538916787981868004206438539248910734713495276883724693574434582104900978079701174539167102706725422582788481727619546235440508214694579 1756026041



