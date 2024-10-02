import os
from flask import Flask, render_template,request, jsonify, redirect, url_for, session, flash
from SPARQLWrapper import SPARQLWrapper, JSON
from rdflib import Graph, Literal, RDF, URIRef, Namespace
from rdflib.namespace import FOAF
import os
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'secretkeyforswmedicalgroup26'

@app.route('/')
def home():
    return render_template('index.html', current_page='home')

@app.route('/about')
def about():
    if 'username' in session:
        return render_template('about.html', current_page='about')
    
    return redirect(url_for('login'))

@app.route('/disease-list')
def diseaseList():
    page = int(request.args.get('page'))
    size = int(request.args.get('size'))
    totalPage = request.args.get('totalPage')
    q = request.args.get('q')

    sparql = SPARQLWrapper("https://id.nlm.nih.gov/mesh/sparql")
    sparql.addCustomParameter('inference', 'true')
    sparql.setReturnFormat(JSON)

    if q:
        sparql.setQuery(f"""
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                    
        SELECT DISTINCT (Count(?name) AS ?totalResult) FROM <http://id.nlm.nih.gov/mesh/2024> 
        WHERE {{ 
            ?d a meshv:Descriptor . 
            ?d rdfs:label ?name .
            ?d meshv:treeNumber ?tn .
            FILTER(REGEX(?name,".*{q}.*", "i")) . 
            FILTER(REGEX(?tn,"C")) 
        }}
        """)
        totalResult = int(sparql.query().convert()['results']['bindings'][0]["totalResult"]["value"])
        lastPage = totalResult/size + 1
        
        sparql.setQuery(f"""
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                        
            SELECT DISTINCT ?d ?name ?tn ?scopeNote FROM <http://id.nlm.nih.gov/mesh/2024>
            WHERE {{ 
            ?d meshv:concept ?concept_o .
            ?concept_o meshv:scopeNote ?scopeNote .
            ?d a meshv:Descriptor . 
            ?d rdfs:label ?name . 
            ?d meshv:treeNumber ?tn .
            FILTER(REGEX(?name, ".*{q}.*", "i")) .
            FILTER(REGEX(?tn, "C"))
        }}
        order by ?name
        offset {(page - 1) * size}
        limit {size}""")
        results = sparql.query().convert()

        jsonResult = []
        for result in results["results"]["bindings"]:
            d_value = result["d"]["value"].split('/')[-1]
            name_value = result["name"]["value"]
            tn_value = result["tn"]["value"].split('/')[-1]
            scopeNote = result["scopeNote"]["value"]
            jsonResult.append({'descr':d_value, 'name':name_value, 'tree':tn_value, 'scopeNote': scopeNote})
        
        return jsonify({'data':jsonResult, 'last_page':lastPage})
    else:
        lastPage = 0
        if totalPage:
            lastPage = totalPage
        else:
            sparql.setQuery(f"""
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                        
            SELECT DISTINCT (Count(?d) AS ?totalResult) FROM <http://id.nlm.nih.gov/mesh/2024> 
            WHERE {{ 
                ?d a meshv:Descriptor . 
                ?d rdfs:label ?name . 
                ?d meshv:treeNumber ?tn . 
                FILTER(REGEX(?tn,"C..$")) 
            }}
            """)
            totalResult = int(sparql.query().convert()['results']['bindings'][0]["totalResult"]["value"])
            lastPage = totalResult/size + 1
        
        sparql.setQuery(f"""
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                        
            SELECT DISTINCT ?d ?name ?tn ?scopeNote FROM <http://id.nlm.nih.gov/mesh/2024>
            WHERE {{ 
            ?d meshv:concept ?concept_o .
            ?concept_o meshv:scopeNote ?scopeNote .
            ?d a meshv:Descriptor . 
            ?d rdfs:label ?name . 
            ?d meshv:treeNumber ?tn .
            FILTER(REGEX(?tn, "C..$"))
        }}
        order by ?name
        offset {(page - 1) * size}
        limit {size}""")
        results = sparql.query().convert()

        jsonResult = []
        for result in results["results"]["bindings"]:
            d_value = result["d"]["value"].split('/')[-1]
            name_value = result["name"]["value"]
            tn_value = result["tn"]["value"].split('/')[-1]
            scopeNote = result["scopeNote"]["value"]
            jsonResult.append({'descr':d_value, 'name':name_value, 'tree':tn_value, 'scopeNote': scopeNote})
        
        return jsonify({'data':jsonResult, 'last_page':lastPage})

@app.route('/diseases')
def diseases():
    if 'username' in session:
        return render_template('diseases.html', current_page='diseases')

    return redirect(url_for('login'))

@app.route('/info/<parentTn>')
def info(parentTn):
    sparql = SPARQLWrapper("https://id.nlm.nih.gov/mesh/sparql")
    sparql.addCustomParameter('inference', 'true')
    sparql.setQuery(f"""
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                    
        SELECT DISTINCT ?d ?name ?tn ?scopeNote FROM <http://id.nlm.nih.gov/mesh/2024>
        WHERE {{
        ?d meshv:concept ?concept_o .
        ?concept_o meshv:scopeNote ?scopeNote .
        ?d a meshv:Descriptor . 
        ?d rdfs:label ?name . 
        ?d meshv:treeNumber ?tn .
        FILTER(REGEX(?tn, "{parentTn}\\\\.\\\\d+$"))
    }}
    order by ?name""")

    sparql.setReturnFormat(JSON)
    results = sparql.query().convert()
    jsonResult = []
    for result in results["results"]["bindings"]:
        d_value = result["d"]["value"].split('/')[-1]
        name_value = result["name"]["value"]
        tn_value = result["tn"]["value"].split('/')[-1]
        scopeNote = result["scopeNote"]['value']
        jsonResult.append({'descr':d_value, 'name':name_value, 'scopeNote': scopeNote, 'tree':tn_value})

    return jsonify({'data':jsonResult})


@app.route('/meds-list')
def medsList():
    page = int(request.args.get('page'))
    size = int(request.args.get('size'))
    totalPage = request.args.get('totalPage')
    q = request.args.get('q')

    sparql = SPARQLWrapper("https://id.nlm.nih.gov/mesh/sparql")
    sparql.addCustomParameter('inference', 'true')
    sparql.setReturnFormat(JSON)

    if q:
        sparql.setQuery(f"""
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                    
        SELECT DISTINCT (Count(?name) AS ?totalResult) FROM <http://id.nlm.nih.gov/mesh/2024> 
        WHERE {{ 
            ?d a meshv:Descriptor . 
            ?d rdfs:label ?name .
            ?d meshv:treeNumber ?tn .
            FILTER(REGEX(?name,".*{q}.*", "i")) . 
            FILTER(REGEX(?tn,"D")) 
        }}
        """)
        totalResult = int(sparql.query().convert()['results']['bindings'][0]["totalResult"]["value"])
        lastPage = totalResult/size + 1
        
        sparql.setQuery(f"""
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                        
            SELECT DISTINCT ?d ?name ?tn ?scopeNote FROM <http://id.nlm.nih.gov/mesh/2024>
            WHERE {{ 
            ?d meshv:concept ?concept_o .
            ?concept_o meshv:scopeNote ?scopeNote .
            ?d a meshv:Descriptor . 
            ?d rdfs:label ?name . 
            ?d meshv:treeNumber ?tn .
            FILTER(REGEX(?name, ".*{q}.*", "i")) .
            FILTER(REGEX(?tn, "D"))
        }}
        order by ?name
        offset {(page - 1) * size}
        limit {size}""")
        results = sparql.query().convert()

        jsonResult = []
        for result in results["results"]["bindings"]:
            d_value = result["d"]["value"].split('/')[-1]
            name_value = result["name"]["value"]
            tn_value = result["tn"]["value"].split('/')[-1]
            scopeNote = result["scopeNote"]["value"]
            jsonResult.append({'descr':d_value, 'name':name_value, 'tree':tn_value, 'scopeNote': scopeNote})
        
        return jsonify({'data':jsonResult, 'last_page':lastPage})
    else:
        lastPage = 0
        if totalPage:
            lastPage = totalPage
        else:
            sparql.setQuery(f"""
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                        
            SELECT DISTINCT (Count(?d) AS ?totalResult) FROM <http://id.nlm.nih.gov/mesh/2024> 
            WHERE {{ 
                ?d a meshv:Descriptor . 
                ?d rdfs:label ?name . 
                ?d meshv:treeNumber ?tn . 
                FILTER(REGEX(?tn,"D..$")) 
            }}
            """)
            totalResult = int(sparql.query().convert()['results']['bindings'][0]["totalResult"]["value"])
            lastPage = totalResult/size + 1
        
        sparql.setQuery(f"""
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX meshv: <http://id.nlm.nih.gov/mesh/vocab#>
                        
            SELECT DISTINCT ?d ?name ?tn ?scopeNote FROM <http://id.nlm.nih.gov/mesh/2024>
            WHERE {{ 
            ?d meshv:concept ?concept_o .
            ?concept_o meshv:scopeNote ?scopeNote .
            ?d a meshv:Descriptor . 
            ?d rdfs:label ?name . 
            ?d meshv:treeNumber ?tn .
            FILTER(REGEX(?tn, "D..$"))
        }}
        order by ?name
        offset {(page - 1) * size}
        limit {size}""")
        results = sparql.query().convert()

        jsonResult = []
        for result in results["results"]["bindings"]:
            d_value = result["d"]["value"].split('/')[-1]
            name_value = result["name"]["value"]
            tn_value = result["tn"]["value"].split('/')[-1]
            scopeNote = result["scopeNote"]["value"]
            jsonResult.append({'descr':d_value, 'name':name_value, 'tree':tn_value, 'scopeNote': scopeNote})
        
        return jsonify({'data':jsonResult, 'last_page':lastPage})

@app.route('/chemicals-meds')
def chemicalsMeds():
    if 'username' in session:
        return render_template('chemicalsMeds.html', current_page='chemicalsMeds')

    return redirect(url_for('login'))

#######################

USER = Namespace("http://example.org/user#")
EX = Namespace("http://example.org/extra#")
g = Graph()
g.bind("foaf", FOAF)
g.bind("ex", EX)

rdf_data_dir = os.path.join(os.path.dirname(__file__), 'data')
user_data_file = os.path.join(rdf_data_dir, 'users.rdf')

if not os.path.exists(rdf_data_dir):
    os.makedirs(rdf_data_dir)

if not os.path.exists(user_data_file):
    with open(user_data_file, 'w') as f:
        f.write('')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        email = request.form['email']
        birthday = request.form['birthday']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message)
            return redirect(url_for('signup'))

        user = URIRef(USER[username])
        g.parse(user_data_file, format='turtle')
        
        if (user, RDF.type, FOAF.Person) in g:
            flash('Username already exists. Please choose a different username.')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        user = URIRef(USER[username])
        g.add((user, RDF.type, FOAF.Person))
        g.add((user, FOAF.name, Literal(username)))
        g.add((user, FOAF.firstName, Literal(firstName)))
        g.add((user, FOAF.lastName, Literal(lastName)))
        g.add((user, FOAF.birthday, Literal(birthday)))
        g.add((user, EX.email, Literal(email)))
        g.add((user, EX.password, Literal(hashed_password.decode('utf-8'))))
        
        #save data
        g.serialize(destination=user_data_file, format='turtle')
        
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        g.parse(user_data_file, format='turtle')
        user = URIRef(USER[username])
        
        if (user, RDF.type, FOAF.Person) in g:
            stored_hashed_password = g.value(user, EX.password)
            if stored_hashed_password and bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                session['username'] = username
                return redirect(url_for('home'))
            else:
                flash('Invalid credentials. Please try again.')
                return redirect(url_for('login'))
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = URIRef(USER[username])
    g.parse(user_data_file, format='turtle')

    if request.method == 'POST':
        first_name = request.form['firstName']
        last_name = request.form['lastName']
        email = request.form['email']
        birthday = request.form['birthday']
        
        g.set((user, FOAF.firstName, Literal(first_name)))
        g.set((user, FOAF.lastName, Literal(last_name)))
        g.set((user, EX.email, Literal(email)))
        g.set((user, FOAF.birthday, Literal(birthday)))
        
        g.serialize(destination=user_data_file, format='turtle')
        
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))

    first_name = g.value(user, FOAF.firstName) or ""
    last_name = g.value(user, FOAF.lastName) or ""
    email = g.value(user, EX.email) or ""
    birthday = g.value(user, FOAF.birthday) or ""
    
    return render_template('profile.html', username=username, first_name=first_name, last_name=last_name, email=email, birthday=birthday)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = URIRef(USER[username])
    g.parse(user_data_file, format='turtle')

    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_new_password = request.form['confirm_new_password']

    if new_password != confirm_new_password:
        flash('New passwords do not match.')
        return redirect(url_for('profile'))
    
    is_valid, message = validate_password(new_password)
    if not is_valid:
        flash(message)
        return redirect(url_for('profile'))

    stored_hashed_password = g.value(user, EX.password)
    if stored_hashed_password and bcrypt.checkpw(current_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        g.set((user, EX.password, Literal(hashed_new_password.decode('utf-8'))))
        g.serialize(destination=user_data_file, format='turtle')
        flash('Password changed successfully.')
    else:
        flash('Current password is incorrect.')

    return redirect(url_for('profile'))

if __name__=='__main__':
    app.run()
    