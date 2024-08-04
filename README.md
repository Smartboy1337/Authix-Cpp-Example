

# AuthixCppExample

## What is Authix?

Authix is a cutting-edge authentication service designed to secure your applications with advanced, reliable, and customizable features. If you’re looking to protect your users' data and enhance your application's security, Authix is the solution you need. Here's what Authix offers:

- **Top-notch Security**: Authix employs state-of-the-art encryption, hashing, and verification algorithms to safeguard your users' credentials and sessions. It also ensures server-side data integrity, providing maximum security for your applications.

- **Seamless Integration**: Authix is built for easy integration with your existing systems. With a user-friendly API and support, getting started is quick and hassle-free. Authix is compatible with multiple platforms, languages, and frameworks, allowing you to work with the tools and technologies you prefer.

- **Innovative Custom Features**: Authix stands out by offering unique, innovative authentication features that go beyond standard services. These features will be unveiled gradually, ensuring you always have access to the latest advancements in authentication.

- **Tailored Solutions**: Authix can provide custom solutions tailored to your specific needs. Whether you have unique authentication requirements or preferences, Authix can work with you to achieve your goals efficiently.

Authix is the ultimate tool to elevate your application's security and make your life easier. Get started today and experience the difference with Authix.

Join our community on Discord or visit our website to learn more:

- **[Discord](https://discord.gg/kzeE3EK3Gg)**
- **[Website](https://authix.cc/)**

## License

When using the Authix example, please adhere to the following licensing terms:

- **No Third-Party Hosting**: You may not provide the software as a hosted or managed service to third parties, especially if it grants users access to a substantial portion of the software's features or functionality.

- **License Key Integrity**: You are not allowed to alter, disable, circumvent, or remove the license key functionality within the software. Additionally, you may not obscure or remove any features protected by the license key.

- **Preservation of Notices**: Do not alter, remove, or obscure any licensing, copyright, or other notices within the software. The use of Authix’s trademarks must comply with applicable laws.

Your compliance with these guidelines is crucial, as considerable effort has gone into developing Authix. We do not tolerate copyright infringement.

## Reporting Bugs and Suggestions

If you encounter any bugs or have suggestions to improve Authix, please join our Discord server and let us know:

- **[Discord](https://discord.gg/kzeE3EK3Gg)**

## Getting Started with AuthixCppExample

To begin, gather the following information from your dashboard:

```cmake
std::string OwnerUUID = xorstr_("00000000000-0000-0000-0000-000000000000000"); // Found on your Dashboard
std::string AppName = xorstr_("Example"); // Your application's name, found on your Dashboard
std::string AppSecretKey = xorstr_("0000000000000000000000000000000000000000000000000000000000000000"); // AppSecret, found on your Dashboard
```

Replace the placeholder data in the `authix.cpp` file with your specific information from the dashboard.

### Using File Stream

1. Drag your file into `Encrypter.exe` (located in the x64 folder).
2. Enter your encryption key and IV key (provided in your dashboard) in the console.
3. Check your download folder for the encrypted file.
4. Upload the encrypted file to a direct download website and post the URL in the dashboard.
5. In the `main.cpp`, use the filename as defined in the dashboard, and everything should work smoothly.

### Important Steps

- **Unzip `Cryptopp.rar`** into `AuthixCppExample-main\AuthixExample\Libs`!
- **Unzip `Dlls.rar`** into `AuthixCppExample-main\x64\Release`!

For a visual guide, refer to this tutorial:

- **[Video Tutorial](https://youtu.be/ie0mgInYtuo)**


Start securing your applications with Authix today!
