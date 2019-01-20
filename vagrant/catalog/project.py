from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for
from flask import flash, session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Coffeeshop, MenuItem, User
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Coffeeshop app"

engine = create_engine('sqlite:///coffeeshop.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(
            string.ascii_uppercase +
            string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ''' " style="width:300px;height:300px;
    border-radius:150px;-webkit-border-radius:150px;
    -moz-border-radius:150px;"> '''
    print "done!"
    return output

# user helper functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')

    if access_token is None:
        response = make_response(json.dumps('User is not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]  # get the JSON attributes

    if result['status'] != '200':
        # In case of invalid token
        response = make_response(json.dumps('Invalid token'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/coffeeshop/<int:coffeeshop_id>/menu/JSON')
def coffeeshopMenuJSON(coffeeshop_id):
    coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
    items = session.query(MenuItem).filter_by(
        coffeeshop_id=coffeeshop.id).all()
    return jsonify(MenuItem=[item.serialize for item in items])


@app.route('/coffeeshop/<int:coffeeshop_id>/menu/<int:menu_id>/JSON')
def menuItmeJSON(coffeeshop_id, menu_id):
    item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(item=item.serialize)


@app.route('/JSON')
@app.route('/coffeeshop/JSON')
def coffeeshopJSON():
    coffeeshops = session.query(Coffeeshop).all()
    return jsonify(coffeeshops=[c.serialize for c in coffeeshops])

################################


@app.route('/')
@app.route('/coffeeshop/')
def displayCoffeeshops():
    coffeeshops = session.query(Coffeeshop).order_by(asc(Coffeeshop.name))
    if 'username' not in login_session:
        return render_template(
            'publiccoffeeshops.html',
            coffeeshops=coffeeshops)
    else:
        return render_template('coffeeshops.html', coffeeshops=coffeeshops)


@app.route('/coffeeshop/new', methods=['GET', 'POST'])
def newCoffeeshop():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCoffeeShop = Coffeeshop(name=request.form['name'], user_id = login_session.get('user_id'))
        session.add(newCoffeeShop)
        session.commit()
        return redirect(url_for('displayCoffeeshops'))
    else:
        return render_template('newCoffeeShop.html')


@app.route('/coffeeshop/<int:coffeeshop_id>/edit', methods=['GET', 'POST'])
def editCoffeeshop(coffeeshop_id):
    editedCoffeeshop = session.query(
        Coffeeshop).filter_by(id=coffeeshop_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedCoffeeshop.user_id != login_session.get('user_id'):
        return """<script>function myFunction()
        {alert('You are not authorized');}
        </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if request.form['name']:
            editedCoffeeshop.name = request.form['name']
            return redirect(url_for('displayCoffeeshops'))
    else:
        return render_template(
            'editCoffeeShop.html',
            coffeeshop=editedCoffeeshop)


@app.route('/coffeeshop/<int:coffeeshop_id>/delete', methods=['GET', 'POST'])
def deleteCoffeeshop(coffeeshop_id):
    coffeeshopToDelete = session.query(
        Coffeeshop).filter_by(id=coffeeshop_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if login_session.get('user_id') != coffeeshopToDelete.user_id:
        return """<script>function myFunction()
        {alert('You are not authorized');}
        </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(coffeeshopToDelete)
        session.commit()
        return redirect(
            url_for(
                'displayCoffeeshops',
                coffeeshop_id=coffeeshop_id))
    else:
        return render_template(
            'deleteCoffeeShop.html',
            coffeeshop=coffeeshopToDelete)


@app.route('/coffeeshop/<int:coffeeshop_id>/')
@app.route('/coffeeshop/<int:coffeeshop_id>/menu')
def displayCoffeShopMenu(coffeeshop_id):
    coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
    items = session.query(MenuItem).filter_by(
        coffeeshop_id=coffeeshop_id).all()
    if 'username' not in login_session:
        return render_template(
            'publicmenu.html',
            items=items,
            coffeeshop=coffeeshop)
    else:
        return render_template('menu.html', items=items, coffeeshop=coffeeshop)


@app.route(
    '/coffeeshop/<int:coffeeshop_id>/menu/new/',
    methods=[
        'GET',
        'POST'])
def addNewMenuItem(coffeeshop_id):
    if 'username' not in login_session:
        return redirect('/login')
    coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
    if login_session.get('user_id') != coffeeshop.user_id:
        return """<script>function myFunction()
        {alert('You are not authorized');}
        </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        newItem = MenuItem(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            coffeeshop_id=coffeeshop.id,
            user_id = coffeeshop.user_id
            )
        session.add(newItem)
        session.commit()
        return redirect(
            url_for(
                'displayCoffeShopMenu',
                coffeeshop_id=coffeeshop.id))
    else:
        return render_template('newmenuitem.html', coffeeshop_id=coffeeshop.id)


@app.route(
    '/coffeeshop/<int:coffeeshop_id>/menu/<int:menu_id>/edit',
    methods=[
        'GET',
        'POST'])
def editMenuItem(coffeeshop_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
    if login_session.get('user_id') != coffeeshop.user_id:
        return """<script>function myFunction()
        {alert('You are not authorized');}
        </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        session.add(editedItem)
        session.commit()
        return redirect(
            url_for(
                'displayCoffeShopMenu',
                coffeeshop_id=coffeeshop.id))
    else:
        return render_template(
            'editmenuitem.html',
            coffeeshop_id=coffeeshop.id,
            menu_id=menu_id,
            item=editedItem)


@app.route(
    '/coffeeshop/<int:coffeeshop_id>/menu/<int:menu_id>/delete',
    methods=[
        'GET',
        'POST'])
def deleteMenuItem(coffeeshop_id, menu_id):
    if 'username' not in login_session:
        return redirect('login')
    coffeeshop = session.query(Coffeeshop).filter_by(id=coffeeshop_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if login_session.get('user_id') != coffeeshop.user_id:
        return """<script>function myFunction()
        {alert('You are not authorized');}
        </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(
            url_for(
                'displayCoffeShopMenu',
                coffeeshop_id=coffeeshop.id))
    else:
        return render_template('deletemenuitem.html', item=itemToDelete)


@app.route('/disconnect')
def disconnect():
    gdisconnect()
    del login_session['gplus_id']
    del login_session['access_token']
    del login_session['username']
    del login_session['email']
    del login_session['picture']

    return redirect(url_for('displayCoffeeshops'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
