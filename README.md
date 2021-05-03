# Wallet-System
A E-wallet system for transfering and storing cash in multiple currencies. access is limited by roles

## Getting Started
### Local setup
To install and run on your local machine clone this repo and change into the project directory then install the requirement
using

```
pip install -r requirement.txt
```
Then run

```
python manage.py db init
```
```
python manage.py runserver
```
this starts a server on your localhost on port 5000 which you can use to interface with it

You can get a list of all api endpoints in the docs at https://wallet-sys.herokuapp.com/api/docs/

### Hosted API
you can interface with the api using this as your base url https://wallet-sys.herokuapp.com

## Technologies Used
The application was built on flask and python, i used swagger for api documentation. the database used was postgres db 
I then hosted the application on heroku. The roles of user are validated using bitwise operations.

### Seeded admin login details
To get instance usage as a admin login in the /user/login route with the following login details

- username: "admin"
- password: "12345678"

