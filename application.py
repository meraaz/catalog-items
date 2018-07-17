import json
import random
import string
from functools import wraps

import httplib2
import requests
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash  # noqa
from flask import make_response
from flask import session as login_session
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config.db.createDB import Base, Item, Category, User

app = Flask(__name__)


FACEBOOK_CREDENTIALS = 'config/facebookCredentials.json'
GOOGLE_CREDENTIALS = 'config/googleCredentials.json'

CLIENT_ID = json.loads(
    open(GOOGLE_CREDENTIALS, 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"


# Connect to DB , and create DB file
engine = create_engine('sqlite:///item_catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------
# CRUD Operations - Categories
# ---------------------------------------

# List All Categories as JSON
@app.route('/api/v1/categories')
def list_categories_json():
    categories = session.query(Category).all()
    return jsonify(Categories=[
        r.serialize for r in categories
    ])


# Show specific Category as JSON
@app.route('/api/v1/category/<int:category_id>')
def show_category_json(category_id):
    category = session.query(Category).\
        filter_by(id=category_id).\
        one()
    return jsonify(Category=category.serialize)


# List All Categories
@app.route('/')
@app.route('/categories')
def list_categories():
    categories = session.query(Category).all()
    return render_template('listCategories.html', categories=categories)


# Show specific Category
@app.route('/category/<int:category_id>')
def show_category(category_id):
    category = session.query(Category).\
        filter_by(id=category_id).\
        one()
    items = session.query(Item).\
        filter_by(category_id=category_id).\
        all()
    return render_template('showCategory.html', category=category, items=items)


# Create New Category
@app.route('/category/create', methods=['GET', 'POST'])
# Login Required to Create
@login_required
def create_category():
    if 'email' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = get_user_id(login_session['email'])
        new_category = Category(
            name=request.form['name'],
            user_id=login_session['user_id']
        )
        session.add(new_category)
        flash('New Category created successfully', 'success')
        session.commit()
        return redirect(url_for('list_categories'))
    else:
        return render_template('createCategory.html')


# Update Existing Category
@app.route('/category/<int:category_id>/update', methods=['GET', 'POST'])
# Login Required to Update
@login_required
def update_category(category_id):
    category = session.query(Category).\
        filter_by(id=category_id).\
        one()
    if category.user_id != login_session['user_id']:
        flash('You are not authorized to update this category', 'danger')
        return redirect(url_for(''))
    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
            flash('Category updated successfully', 'success')
            return redirect(url_for('list_categories'))
    else:
        return render_template('updateCategory.html', category=category)


# Delete Existing Category
@app.route('/category/<int:category_id>/delete', methods=['GET', 'POST'])
# Login Required to Delete
@login_required
def delete_category(category_id):
    category = session.query(Category). \
        filter_by(id=category_id). \
        one()
    if category.user_id != login_session['user_id']:
        flash('You are not authorized to delete this category', 'danger')
        return redirect(url_for(''))
    if request.method == 'POST':
        session.delete(category)
        flash('Category deleted successfully')
        session.commit()
        return redirect(url_for('list_categories'))
    else:
        return render_template('deleteCategory.html', category=category)


# ---------------------------------------
# CRUD Operations - Items
# ---------------------------------------
# List All Items as JSON
@app.route('/api/v1/items')
def list_items_json():
    items = session.query(Item).all()
    return jsonify(Items=[
        r.serialize for r in items
    ])


# List All Items
@app.route('/items')
def list_items():
    items = session.query(Item).all()
    return render_template('listItems.html', items=items)


# Show specific Item as JSON
@app.route('/api/v1/category/<int:category_id>/item/<int:item_id>')
def show_item_json(category_id, item_id):
    category = session.query(Category). \
        filter_by(id=category_id). \
        one()
    item = session.query(Item).\
        filter_by(id=item_id).\
        one()
    return jsonify(category=category.serialize, item=item.serialize)


# Show Specific Item Details
@app.route('/item/<int:item_id>')
def show_item(item_id):
    item = session.query(Item). \
        filter_by(id=item_id). \
        one()
    return render_template('showItem.html', item=item)


# Create New Item
@app.route('/item/create', methods=['GET', 'POST'])
# Login Required to Create
@login_required
def create_item():
    if 'email' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    if request.method == 'POST':
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = get_user_id(login_session['email'])
        new_item = Item(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            category_id=request.form['category'],
            user_id=login_session['user_id']
        )
        session.add(new_item)
        session.commit()
        flash('New Item created successfully', 'success')
        return redirect(url_for('list_items'))
    else:
        return render_template('createItem.html', categories=categories)


# Update Existing Item
@app.route('/item/<int:item_id>/update', methods=['GET', 'POST'])
# Login Required to Update
@login_required
def update_item(item_id):
    categories = session.query(Category).all()
    item = session.query(Item).\
        filter_by(id=item_id).\
        one()
    if item.user_id != login_session['user_id']:
        flash('You are not authorized to update this item', 'danger')
        return redirect(url_for(''))
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']

        if request.form['description']:
            item.description = request.form['description']

        if request.form['price']:
            item.price = request.form['price']

        if request.form['category']:
            item.category_id = request.form['category']

        session.add(item)
        session.commit()
        flash('Item updated successfully', 'success')
        return redirect(url_for('list_items'))
    else:
        return render_template(
            'updateItem.html', item=item, categories=categories
        )


# Delete Existing Item
@app.route('/item/<int:item_id>/delete', methods=['GET', 'POST'])
# Login Required to Delete
@login_required
def delete_item(item_id):
    item = session.query(Item). \
        filter_by(id=item_id). \
        one()
    if item.user_id != login_session['user_id']:
        flash('You are not authorized to delete this item', 'danger')
        return redirect(url_for(''))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item deleted successfully', 'success')

        return redirect(url_for('list_items'))
    else:
        return render_template('deleteItem.html', item=item)

# --------------------------------------
# Login Handling
# --------------------------------------


# Login route, create anit-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# FB Login
@app.route('/fblogin', methods=['GET', 'POST'])
def fblogin():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = bytes.decode(request.data, 'utf-8')

    # print ("access token received %s " % access_token)

    app_id = json.loads(
        open(FACEBOOK_CREDENTIALS, 'r').read()
    )['web']['app_id']
    app_secret = json.loads(
        open(FACEBOOK_CREDENTIALS, 'r').read()
    )['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)  # noqa

    h = httplib2.Http()
    result = json.loads(bytes.decode(h.request(url, 'GET')[1]), 'utf-8')
    # Use token to get user info from API
    token = result['access_token']
    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token     # noqa
    h = httplib2.Http()
    data = json.loads(bytes.decode(h.request(url, 'GET')[1]), 'utf-8')
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    data = json.loads(bytes.decode(h.request(url, 'GET')[1]), 'utf-8')

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user()
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' "style = "width: 300px; height: 300px;border-radius: 150px; '
    output += ' -webkit-border-radius: 150px;-moz-border-radius: 150px;">'

    flash("Now logged in as %s" % login_session['username'])
    return output


# Logout from Facebook
@app.route('/fblogout')
def fblogout():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)  # noqa
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# CONNECT - Google login get token
@app.route('/glogin', methods=['GET', 'POST'])
def glogin():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(GOOGLE_CREDENTIALS, scope='')
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
    result = json.loads(bytes.decode(h.request(url, 'GET')[1]), 'utf-8')
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
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if not create new user
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user()
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '  # noqa
    flash("you are now logged in as %s" % login_session['username'], 'success')
    print("done!")
    return output


# Logout and reset session data
@app.route('/glogout')
def glogout():
    # Get user credentials from session
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('User Logged out.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # execute HTTP GET request to revoke current token
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset the user's session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # token given is invalid
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# User helper functions
# Get User ID using his email
def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


# Get User Information
def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Create New User
def create_user():
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Logout based on provider and
# Rest Login Session Data
@app.route('/logout')
def logout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            glogout()
            if 'gplus_id' in login_session:
                del login_session['gplus_id']
            if 'credentials' in login_session:
                del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fblogout()
            del login_session['facebook_id']
        if 'username' in login_session:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'picture' in login_session:
            del login_session['picture']
        if 'user_id' in login_session:
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully logged out.", 'success')
        return redirect(url_for('list_categories'))
    else:
        flash("You were not logged in", 'danger')
        return redirect(url_for('list_categories'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
