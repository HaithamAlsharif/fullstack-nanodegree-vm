# Project Overview
This project is a Coffeeshop menu system, displaying the different Coffeeshops we have and all the item menues each coffeshop with full manipulation of the coffeeshops and thier items using the following CRUD actions: create, read, update, and delete.

# Project Requirements:
What you need to ruin this program:
- Python 3.7.1
- Flask
- Sqlalchemy
- OAuth2

# How to run the project:
After the virtual machine (vagrant) go to /vagrant/catalog then:
There are two steps to run this project:
## First: Set up the database:
- Run "Python database_setup.py" to set up the models and the relations of the database
- Run "Python data.py" to fill in dummy data into the tables.
## Second: Run the website:
- Run: "Python project.py"
- Go to: "http://localhost:8000"

# JSON Endpoints:
I have provided three JSON endpoints for three different data:
- coffeeshopJSON: which is for all the coffeeshops available and can be accessed through:
  - "localhost:8000/JSON" or "http://localhost:8000/coffeeshop/JSON"
  
- coffeeshopMenuJSON: which is for all the menu items in a particular coffeeshop and can be accessed through:
  - "localhost:8000/coffeeshop/<int:coffeeshop_id>/menu/JSON"
   
- menuItmeJSON: which is for a particular item in the menu of the particular coffeeshop and can be accessed through:
  - "localhost:8000//coffeeshop/<int:coffeeshop_id>/menu/<int:menu_id>/JSON"