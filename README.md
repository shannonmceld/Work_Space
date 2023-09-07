# Work_Space
Projects to further my coding experiences

<blockquote class="tiktok-embed" cite="https://www.tiktok.com/@iamshannonyinka/video/7276145381422107950" data-video-id="7276145381422107950" style="max-width: 605px;min-width: 325px;" > <section> <a target="_blank" title="@iamshannonyinka" href="https://www.tiktok.com/@iamshannonyinka?refer=embed">@iamshannonyinka</a> <p>Hey, new project has finished </p> <a target="_blank" title="♬ original sound  - Shannon Mcelderry" href="[https://www.tiktok.com/music/original-sound-Shannon-Mcelderry-7276145481661696810?refer](https://www.tiktok.com/@iamshannonyinka/video/7276145381422107950?is_from_webapp=1&sender_device=pc&web_id=7264359559400457770)=embed">♬ original sound  - Shannon Mcelderry</a> </section> </blockquote> <script async src=["https://www.tiktok.com/embed.js"](https://www.tiktok.com/@iamshannonyinka/video/7276145381422107950?is_from_webapp=1&sender_device=pc&web_id=7264359559400457770)></script>


# The Vault
#### Video Demo:  <URL HERE>
#### Description: Password Manager

#### The Vault
This repository contains a password manager that allows you to securely encrypt and decrypt your passwords using a strong key generator. It provides a convenient and safe way to store and manage your passwords.

#### Features
I decided to build a flask app. Flask is a web framework that allows developers to build lightweight web applications quickly and easily with Flask Libraries. It was developed by Armin Ronacher, leader of the International Group of Python Enthusiasts (POCCO). It is basically based on the WSGI toolkit and Jinja2 templating engine.
There are 12 templates pages with 14 different routes. 
Error 404 not found is one of the most common issues you may encounter while browsing. This template will direct you to the root route of login page depending on if you are logged in or not.
The login template holds three forms. The login form, forgotten password, and forgotten username, and these have three functions. 
Login: will ask you to enter your password and username. The server and the template both are set up so the form cannot be submitted empty. Both inputs are required to move on. Once the form is submitted, the program will query the submitted information in the SQL Server. There is an account database that holds the accounts table. The program will compare password that Posted from the form with the one stored in the account database. Since the password that is stored in the accounts table is hash. It will also hash the password from the form. It will also compare the username that was also queried when posted. If these items match the user will be granted login access. If not, the user will be required to try again with a flash message that tell user Wrong username or password.
Forgot Password: will prompt for an email, username, phone number, password, and confirmation password.  It also requires input for all fields via server and html form. Users will not be able to submit forms without required fields. All these field was used during the registration process. The program will query for the input within the database if the information matches, then the user can proceed with updating its password. If not, the program will render back the forgotten password template with a flash message to explain why the password was not changed.
Forgot Username: this function asks the user for their email. The server and html template have requirements before the form can be submitted. If requirements are not met the template will render forgot username template with a flash message explaining the circumstances. The program will then query the database for input email and see if they match. If they match the program will flash a message with user username if not the program will flash back with error message explaining email was not in database.
Log out: this function simply clears the session id. So, the user will be logged out of their account.
Register: will prompt for an email, username, phone number, password, and confirmation password.  It also requires input for all fields via server and html form. Users will not be able to submit forms without required fields. No username email or phone number can be used twice. The program will query within the database and see if the input information already exists. If so, the program will render the register template with a flash message explaining the circumstance. If input information does not match the information in the database, then the program will allow user to insert new information within database which will also creating an account. Then the user will be logged into the said account.
Add: the add function allows users to add profiles to their account. These profiles are in the same account database but profile table. The form prompts users for email, username, URL, password, and confirmation password. The server and html template both require the form to be filled out in its entirety. If not, the form will return with flash message encouraging user to fill out empty field. The add profile function does not hash the password, it instead uses AES encryption. The encryption key is generated by Python OS 32 bytes, ensuring they are stored securely. The key used to encrypt the password is stored in ENV file which is stored in the root of this code space. I used the Dotenv Package to access the file. The dotenv package looks for a file that is literally called. env, I chose encryption because I wanted the user to be able to see the password on the detail page, and hash does not allow un-hashing. The add function also does not have the same required password pattern as the register function because the passwords that were created might have been created with slightly different requirements and pattern in other accounts. The add function will take the form input information and insert it into the profile and details table within the database.  Profiles is the home page so once sign in, user will see URL and usernames for all profile in a table.
Change: function is a password rest for user who know their password and just want to change it. It only can be accessed if the user is logged in. This function renders a template through the get method. For prompt users for a new password and confirmation password. If the form is not filled in its entirety, it will return the reset password template and flash a message with missing field. If both inputs are filled in the program will see if the password matches the confirmation password if not again it will return template with a flash message informing the user. If so, it will hash the password and then query into the account table and update the old password with the new one where id is equal to user session id.
Generate/Generate Symbol: Both functions generate password using secrets module. The secrets module is used for generating random numbers for managing important data such as passwords, account authentication, security tokens, and related secrets, that are cryptographically strong. This module is responsible for providing access to the most secure source of randomness. Generate generates password without symbol, and Generate Symbol generates password with symbol. The functions use string library to import ASCII letters and digits. The symbols are the same pattern I used for the verify password in the register account function. It uses a four loop in the range of eight and twenty to join all characters. Once the form has been submitted, either button under with symbol expression, or button under without symbol expression, it will return page with flash message of the newly generated password.
Index Function: query into the profiles table to render table with username and website the username is connected to. This renders the index template that shows the table of profile. With this table, you can navigate to the detail’s temple.
Detail function: take the information already provided in the profile table on the index template to query within the details table. It then renders details about specific profile such as email, date profile was created, username, password, and website the profiles are attached to. Once the query is returned, if it does not equal one it will return index page and flash message that details are not available, if it is a match the password from the query is then decrypted with the same key stored in ENV file and decoded back to a string. Jinja then shows the password within the table. Within the detail template there is the Update and Delete function.
Delete: uses user session id, website, username from the detail form. It queries this information to delete profile from the details and profiles table. Once deleted it returns to the index template.
Update: render template with form that prompt user for username, URL, password, and confirmation password. If form is submitted with empty field template update is returned with a flash message with reasoning. Once the form is filled in its entirety, and the password matches confirmation password, the password is then encrypted with AES256 Cryptology. It queries into details and if the detail in details matches the form it will update the password, return home and flash a message to inform user password is now updated. If not, it will return template update with a flash message.
User-Friendly Interface: The program provides a simple web application interface that allows you to add new passwords, view existing ones easily and generate secure password without creating an account/session.
Type URL into a web browser. Once you are at the website you can choose to generate a password without an account, or you will have to create an account to use The Vault password manager.
Contributions to this password manager project are welcome! If you find any issues, have suggestions for improvements, or would like to add new features, please open an issue or submit a pull request.
Acknowledgements
This project utilizes the cryptography library for encryption and decryption functionality.

