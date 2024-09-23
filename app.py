from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import secrets
from pymysql import NULL
from flask import jsonify
import hashlib
from functools import wraps
from datetime import datetime, timedelta


app = Flask(__name__)

# Generate a random secret key
secret_key = secrets.token_hex(16)
app.secret_key = secret_key

# Configure MySQL connection
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'air_reservation'

mysql = MySQL(app)

# Define the login_required decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            
            if role is not None and session.get('user_type') != role:
                return "Unauthorized", 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    
    # Redirect to the default home page
    return redirect(url_for('index'))

def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/login')
def login():
	return render_template('login.html')

@app.route('/customerHome')
@login_required(role='customer')
def customerHome():
    return render_template('customer_home.html')

@app.route('/staffHome')
@login_required(role='staff')
def staffHome():
    username = session.get('username')
    return render_template('staff_home.html', username=username)

@app.route('/agentHome')
@login_required(role='agent')
def agentHome():
    return render_template('agent_home.html')

#Authenticates the login
@app.route('/loginAuth', methods=['GET', 'POST'])
def loginAuth():
    # grabs information from the forms
    username = request.form['username']
    password = request.form['password']
    role = request.form['user_type']

    # cursor used to send queries
    cursor = mysql.connection.cursor()

    # execute query based on role
    if role == 'customer':
        query = "SELECT password FROM customer WHERE email = %s"
        home_page = 'customerHome'
    elif role == 'staff':
        query = "SELECT password FROM airline_staff WHERE username = %s"
        home_page = 'staffHome'
    elif role == 'agent':
        query = "SELECT password FROM booking_agent WHERE email = %s"
        home_page = 'agentHome'
    else:
        # Invalid role, handle appropriately (redirect, display error message, etc.)
        return redirect(url_for('login'))

    # executes query
    cursor.execute(query, (username,))

    # stores the results in a variable
    data = cursor.fetchone()

    cursor.close()

    error = None
    if data:
        # Verify password
        hashed_password_from_db = data[0]
        print(hashed_password_from_db)  # Extract the hashed password from the tuple
        if hashed_password_from_db == md5_hash(password):  # Compare the hashed passwords
            # creates a session for the user
            session['username'] = username
            session['user_type'] = role
            return redirect(url_for(home_page))
        else:
            error = 'Invalid password'
    else:
        error = 'Invalid login or username'
    return render_template('login.html', error_message=error)
    
@app.route('/register')
def register():
	return render_template('register.html')


@app.route('/registerAuth', methods=['GET', 'POST'])
def registerAuth():
    if request.method == 'POST':
        selected_role = request.form.get('selectedRole')

        if selected_role == 'customer':
            home_page = 'customerHome'
            c_first_name = request.form.get('customer_first_name', NULL)
            c_last_name = request.form.get('customer_last_name', NULL)
            c_email = request.form.get('customer_email')
            c_pass = request.form.get('customer_password')
            c_cpass = request.form.get('customer_cpassword')
            phone_num = request.form.get('customer_phone_num', NULL)
            c_dob = request.form.get('customer_dob', NULL)
            building =   request.form.get('building_num', NULL)
            street = request.form.get('street', NULL)
            city = request.form.get('city', NULL)
            state_region = request.form.get('state_region', NULL)
            country = request.form.get('country', NULL)
            postal_code = request.form.get('postal_code', NULL)
            passport_num = request.form.get('passport_number', NULL)
            passport_exp = request.form.get('passport_expiry_date', NULL)
            passport_country = request.form.get('passport_country', NULL)

            error = None
            if c_pass != c_cpass:
                error = "passwords don't match"
                return render_template('register.html', error_message=error, selected_role=selected_role)
            else:
                c_pass = md5_hash(c_pass)
                cursor = mysql.connection.cursor()
                cursor.execute("INSERT INTO customer (email, last_name, first_name, password, building_number, street, city, state_region, country, postal_code, phone_number, passport_number, passport_expiration, passport_country, date_of_birth) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (c_email, c_last_name, c_first_name, c_pass, building, street, city, state_region, country, postal_code, phone_num, passport_num, passport_exp, passport_country, c_dob))
                mysql.connection.commit()
                cursor.close()
                session['username'] = c_email
                session['user_type'] = selected_role

        elif selected_role == 'staff':
            home_page = 'staffHome'
            s_airline = request.form['airline']
            s_first_name = request.form['staff_first_name']
            s_last_name = request.form['staff_last_name']
            s_dob = request.form['staff_dob']
            s_username = request.form['staff_username']
            s_pass = request.form['staff_password']
            s_cpass = request.form['staff_cpassword']
            
            error = None
            if s_pass != s_cpass:
                error = "passwords don't match"
                return render_template('register.html', error_message=error, selected_role=selected_role)
            else:
                s_pass = md5_hash(s_pass)
                cursor = mysql.connection.cursor()
                cursor.execute("INSERT INTO airline_staff (airline_name, first_name, last_name, date_of_birth, username, password) VALUES (%s, %s, %s, %s, %s, %s)", (s_airline, s_first_name, s_last_name, s_dob, s_username, s_pass))
                mysql.connection.commit()
                cursor.close()
                session['username'] = s_username
                session['user_type'] = selected_role

        elif selected_role == 'agent':
            home_page = 'agentHome'
            a_username = request.form['agent_username']
            a_pass = request.form['agent_password']
            a_cpass = request.form['agent_cpassword']
            
            error = None
            if a_pass != a_cpass:
                error = "passwords don't match"
                return render_template('register.html', error_message=error, selected_role=selected_role)

            else:
                a_pass = md5_hash(a_pass)
                cursor = mysql.connection.cursor()
                cursor.execute("INSERT INTO booking_agent (email, password) VALUES (%s, %s)", (a_username, a_pass))
                mysql.connection.commit()
                cursor.close()
                session['username'] = a_username
                session['user_type'] = selected_role
        
        # Optionally, you can redirect the user to a success page after registration
        return redirect(url_for(home_page))
    else:
        return render_template('register.html')

def search_flights(departure, arrival, departure_date, return_date=None):
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT flight_num, airline_name, dep_a.name AS departure_airport, dep_a.city AS departure_city, departure_time, arr_a.name AS arrival_airport, arr_a.city AS arrival_city, arrival_time, price, airplane_id FROM flight f JOIN airport dep_a ON f.departure_airport = dep_a.name JOIN airport arr_a ON f.arrival_airport = arr_a.name WHERE ((dep_a.name = %s OR dep_a.city = %s) AND (arr_a.name = %s OR arr_a.city = %s) AND DATE(departure_time) = %s AND status = 'Upcoming')", 
                   (departure, departure, arrival, arrival, departure_date))
    flights = cursor.fetchall()
    print (flights)
    
    cursor.close()
    return flights

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/spendingTracker')
@login_required(role='customer')
def spending_tracker():
    email = session.get('username')
    cursor = mysql.connection.cursor()
    query1 = """
        SELECT SUM(price) 
        FROM ticket t 
        NATURAL JOIN flight f
        WHERE customer_email = %s
    """
    cursor.execute(query1, (email,))
    total_spending = cursor.fetchone()[0]

    query2 = """
        SELECT SUM(price)
        FROM ticket t
        NATURAL JOIN flight f
        WHERE customer_email = %s AND
        t.date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
    """
    cursor.execute(query2, (email,))
    year_spending = cursor.fetchone()[0]

    query3 = """
        SELECT 
            YEAR(t.date) AS year,
            MONTH(t.date) AS month,
            SUM(price) AS total_spent
        FROM 
            ticket t
        NATURAL JOIN 
            flight f
        WHERE 
            customer_email = %s
            AND t.date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY 
            YEAR(t.date), MONTH(t.date)
        ORDER BY 
            year ASC, month ASC
    """
    cursor.execute(query3, (email,))
    six_month_spending = cursor.fetchall()

    cursor.close()

    # Construct a dictionary to hold all the spending data
    spending_data = {
        'total_spending': total_spending,
        'year_spending': year_spending,
        'six_month_spending': six_month_spending
    }

    # Close the database cursor
    cursor.close()

    # Convert spending data to JSON format
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        json_spending_data = jsonify(spending_data)
        print("Spending Data")
        print(json_spending_data)
        return(json_spending_data)
    else:
        # Render the template along with the JSON data
        return render_template('customer_spending.html', spending_data=spending_data)

@app.route('/search', methods=['POST'])
def search():
    if request.method == 'POST':
        departure = request.form['departure']
        arrival = request.form['destination']
        departure_date = request.form['departureDate']
        return_date = request.form.get('returnDate')

        flights = search_flights(departure, arrival, departure_date, return_date)
        print(flights)

        if not flights:
            message = "Sorry! No flights found. Please try another search."
        else:
            message = None

        # Return the search results as JSON
        return jsonify({'flights': flights, 'message': message})

    # This route should only be accessed via POST requests
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/view-status', methods=['POST'])
def view_status():
    if request.method == 'POST':
        # Get form data
        flight_airline = request.form['flightAirline']
        flight_number = request.form['flightNumber']
        flight_date = request.form['flightDate']
        search_type = request.form['searchType']

        # Construct the SQL query based on the search type
        if search_type == 'arrival':
            sql_query = "SELECT status FROM flight WHERE airline_name = %s AND flight_num = %s AND DATE(arrival_time) = %s"
        else:  # Departure search
            sql_query = "SELECT status FROM flight WHERE airline_name = %s AND flight_num = %s AND DATE(departure_time) = %s"

        # Execute the SQL query
        cursor = mysql.connection.cursor()
        cursor.execute(sql_query, (flight_airline, flight_number, flight_date))
        flight_status = cursor.fetchone()
        if flight_status:
            status_dict = {'status': flight_status[0]}
        else:
            status_dict = {'status': 'Not found'}  # Or any appropriate message
        return jsonify({'flightStatus': status_dict})

@app.route('/check-seat-availability', methods=['POST'])
@login_required()
def check_seat_availability_route():
    data = request.json  # Extract flight details from the request
    airplane_id = data.get('airplane_id')
    flight_number = data.get('flight_number')
    airline_name = data.get('airline_name')

    # Call the check_seat_availability function
    available = check_seat_availability(airplane_id, flight_number, airline_name)
    print(available)
    # Return JSON response indicating seat availability
    return jsonify({'available': available})

def check_seat_availability(airplane_id, flight_number, airline_name):
    cursor = mysql.connection.cursor()

    try:
        # Query to get total seats of the airplane
        cursor.execute("SELECT seats FROM airplane WHERE id = %s", (airplane_id,))
        total_seats = cursor.fetchone()[0]

        # Query to get the number of booked seats for the given flight
        cursor.execute("SELECT COUNT(*) AS num_booked FROM ticket WHERE flight_num = %s AND airline_name = %s", (flight_number, airline_name))
        booked_seats = cursor.fetchone()[0]

        # Calculate available seats
        available_seats = total_seats - booked_seats

        if available_seats > 0:
            print("Yes there's seats")
            return True
        else:
            return False
    except Exception as e:
        print("Error:", e)
        return False
    finally:
        cursor.close()

@app.route('/update-customer-info', methods=['POST'])
@login_required()
def update_customer_info():
    print("Start of customer update")
    customer_info = request.json
    email = session.get('username')
    phone_number = customer_info['phoneNumber']
    passport_number = customer_info['passportNumber']
    passport_expiration_date = customer_info['passportExpirationDate']
    passport_country = customer_info['passportCountry']
    building_number = customer_info['buildingNumber']
    street = customer_info['street']
    city = customer_info['city']
    state_region = customer_info['state']
    country = customer_info['country']
    postal_code = customer_info['postalCode']
    
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE customer SET passport_number = %s, passport_expiration = %s, passport_country = %s, building_number = %s, street = %s, city = %s, state_region = %s, country = %s, postal_code = %s, phone_number = %s WHERE email = %s", (passport_number, passport_expiration_date, passport_country, building_number, street, city, state_region, country, postal_code, phone_number, email))
    mysql.connection.commit() #!
    cursor.close()
    print("after update customer")
    return jsonify({'message': 'Customer info updated successfully'})

@app.route('/book-ticket', methods=['POST'])
@login_required
def book_ticket():
    print("start of booking ticket")
    ticket_info = request.json
    flight_num = ticket_info['flightNumber']
    airline_name = ticket_info['airlineName']
    customer_email = session.get('username')
    
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO ticket (flight_num, airline_name, customer_email) VALUES (%s, %s, %s)", (flight_num, airline_name, customer_email))
    mysql.connection.commit() #!
    cursor.close()
    print("after ticket insert")
    return jsonify({'message': 'Ticket booked successfully'})

def get_available_seats(flight_number, airline_name, airplane_id):
    cursor = mysql.connection.cursor()
    print("checking availability")
    try:
        # Query to get total seats of the airplane
        cursor.execute("SELECT seats FROM airplane WHERE id = %s", (airplane_id,))
        total_seats_row = cursor.fetchone()

        if total_seats_row is None:
            raise Exception("No airplane found with id:", airplane_id)

        total_seats = total_seats_row[0]

        # Query to get the number of booked seats for the given flight
        cursor.execute("SELECT COUNT(*) AS num_booked FROM ticket WHERE flight_num = %s AND airline_name = %s", (flight_number, airline_name))
        booked_seats = cursor.fetchone()[0]

        # Calculate available seats
        available_seats = total_seats - booked_seats
        return {'availableSeats': available_seats}  # Return dictionary instead of JSON response
    except Exception as e:
        print("Error:", e)
        return {'error': str(e)}  # Return error response as dictionary
    finally:
        cursor.close()


@app.route('/check_seats', methods=['POST'])
@login_required()
def check_seats():
    data = request.json
    print(data)
    flight_number = data.get('flightNumber')
    airline_name = data.get('airlineName')
    airplane_id = data.get('airplaneID')

    # Perform database query to get available seat count
    # Replace this with your actual database query
    available_seats = get_available_seats(flight_number, airline_name, airplane_id)
    print(available_seats)
    
    # Return available seat count as JSON response
    return jsonify({'availableSeats': available_seats})

@app.route('/bookings', methods=['POST'])
@login_required(role='customer')
def book_flight():
    try:
        # Extract booking data from the request
        booking_data = request.json
        email = session.get('username')

        flight_number = booking_data.get('flightNumber')
        airline_name = booking_data.get('airlineName')
        phone_number = booking_data.get('phoneNumber')
        passport_number = booking_data.get('passportNumber')
        passport_expiration_date = booking_data.get('passportExpirationDate')
        passport_country = booking_data.get('passportCountry')
        building_number = booking_data.get('buildingNumber')
        street = booking_data.get('street')
        city = booking_data.get('city')
        state = booking_data.get('state')
        country = booking_data.get('country')
        postal_code = booking_data.get('postalCode')

        print(email)
        print(flight_number)
        print(airline_name)

        # Update customer information
        cursor = mysql.connection.cursor()
        cursor.execute("""
            UPDATE customer SET 
            passport_number = %s, 
            passport_expiration = %s, 
            passport_country = %s, 
            building_number = %s, 
            street = %s, 
            city = %s, 
            state_region = %s, 
            country = %s, 
            postal_code = %s, 
            phone_number = %s 
            WHERE email = %s""",
            (passport_number, passport_expiration_date, passport_country, building_number, street, city, state, country, postal_code, phone_number, email))
        
        # Insert ticket information
        cursor.execute("INSERT INTO ticket (flight_num, airline_name, customer_email) VALUES (%s, %s, %s)", (flight_number, airline_name, email))

        # Commit the transaction
        mysql.connection.commit()
        cursor.close()

        # Send a success response
        response = {'message': 'Booking successful'}
        return jsonify(response), 200

    except Exception as e:
        # If any error occurs, rollback the transaction and return an error response
        mysql.connection.rollback()
        cursor.close()
        error_message = str(e)
        return jsonify({'error': error_message}), 500


@app.route('/buy-ticket', methods=['GET', 'POST'])
@login_required()
def buy_ticket():
    # Extract flight details from query parameters
    flight_details = {
        'flight_number': request.args.get('flight_number'),
        'airline_name': request.args.get('airline_name'),
        'departure_airport': request.args.get('departure_airport'),
        'departure_city': request.args.get('departure_city'),
        'arrival_airport': request.args.get('arrival_airport'),
        'arrival_city': request.args.get('arrival_city'),
        'departure_time': request.args.get('departure_time'),
        'arrival_time': request.args.get('arrival_time'),
        'price': request.args.get('price'),
        'airplane_id': request.args.get('airplane_id')
    }
    print("rendering buy_ticket page")
    return render_template('buy_ticket.html', flight=flight_details)

@app.route('/my_flights', methods=['GET'])
@login_required(role='customer')
def my_flights():
    # Fetch flight data from the database
    query = """
        SELECT airline_name, flight_num, dep_a.name AS departure_airport, dep_a.city AS departure_city, departure_time, arr_a.name AS arrival_airport, arr_a.city AS arrival_city, arrival_time, COUNT(*) AS num_tickets
        FROM ticket NATURAL JOIN (flight f JOIN airport dep_a ON f.departure_airport = dep_a.name JOIN airport arr_a ON f.arrival_airport = arr_a.name)
        WHERE customer_email = %s AND status = 'Upcoming'
        GROUP BY airline_name, flight_num, departure_airport, departure_time, arrival_airport, arrival_time
    """
    email = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute(query, (email,))
    user_flights = cursor.fetchall()

    # Convert flight data to JSON format
    formatted_flights = []
    for flight in user_flights:
        formatted_flight = {
            'airline_name': flight[0],
            'flight_num': flight[1],
            'departure_airport_code': flight[2],
            'departure_airport_city': flight[3],
            'departure_time': flight[4].strftime("%Y-%m-%d %H:%M:%S"),
            'arrival_airport_code': flight[5],
            'arrival_airport_city': flight[6],
            'arrival_time': flight[7].strftime("%Y-%m-%d %H:%M:%S"),
            'num_tickets': flight[8]
        }
        formatted_flights.append(formatted_flight)

    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # If it's an AJAX request, return JSON data
        return jsonify(formatted_flights)
    else:
        # If it's a regular HTTP request, render the template
        return render_template('c_view_my_flights.html', flights=user_flights)

def agent_search_flights(airlines, departure, arrival, departure_date, return_date=None):
    cursor = mysql.connection.cursor()

    query = """
        SELECT flight_num, airline_name, dep_a.name AS departure_airport, dep_a.city AS departure_city,
               departure_time, arr_a.name AS arrival_airport, arr_a.city AS arrival_city, arrival_time,
               price, airplane_id
        FROM flight f
        JOIN airport dep_a ON f.departure_airport = dep_a.name
        JOIN airport arr_a ON f.arrival_airport = arr_a.name
        WHERE ((dep_a.name = %s OR dep_a.city = %s)
               AND (arr_a.name = %s OR arr_a.city = %s)
               AND DATE(departure_time) = %s
               AND status = 'Upcoming'
               AND airline_name IN ({})
        )
        """.format(','.join(['%s'] * len(airlines)))

    search_parameters = (departure, departure, arrival, arrival, departure_date) + tuple(airlines)
    cursor.execute(query, search_parameters)
    flights = cursor.fetchall()
    print (flights)
    
    cursor.close()
    return flights

@app.route('/agentSearch', methods=['POST'])
@login_required(role='agent')
def agentSearch():
    if request.method == 'POST':
        departure = request.form['departure']
        arrival = request.form['destination']
        departure_date = request.form['departureDate']
        return_date = request.form.get('returnDate')
        email = session.get('username')

        cursor = mysql.connection.cursor()
        query = "SELECT airline_name FROM work_for WHERE booking_agent_email = %s"
        cursor.execute(query, (email,))
        airlines = cursor.fetchall()

        cursor.close()

        flights = agent_search_flights(airlines, departure, arrival, departure_date, return_date)
        print(flights)

        if not flights:
            message = "Sorry! No flights found. Please try another search."
        else:
            message = None

        # Return the search results as JSON
        return jsonify({'flights': flights, 'message': message})

    # This route should only be accessed via POST requests
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/agentBookings', methods=['POST'])
@login_required(role='agent')
def agent_book_flight():
    try:
        # Extract booking data from the request
        booking_data = request.json
        agent_email = session.get('username')

        customer_email = booking_data.get('customerEmail')
        flight_number = booking_data.get('flightNumber')
        airline_name = booking_data.get('airlineName')
        phone_number = booking_data.get('phoneNumber')
        passport_number = booking_data.get('passportNumber')
        passport_expiration_date = booking_data.get('passportExpirationDate')
        passport_country = booking_data.get('passportCountry')
        building_number = booking_data.get('buildingNumber')
        street = booking_data.get('street')
        city = booking_data.get('city')
        state = booking_data.get('state')
        country = booking_data.get('country')
        postal_code = booking_data.get('postalCode')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT booking_agent_id FROM booking_agent WHERE email = %s", (agent_email,))
        agent_id = cursor.fetchone()
        # Insert ticket information
        cursor.execute("INSERT INTO ticket (flight_num, airline_name, booking_agent_id, customer_email) VALUES (%s, %s, %s, %s)", (flight_number, airline_name, agent_id, customer_email))

        # Commit the transaction
        mysql.connection.commit()
        cursor.close()

        # Send a success response
        response = {'message': 'Booking successful'}
        return jsonify(response), 200

    except Exception as e:
        # If any error occurs, rollback the transaction and return an error response
        mysql.connection.rollback()
        cursor.close()
        error_message = str(e)
        app.logger.error("An error occurred while booking: %s", error_message)  # Log the error message
        return jsonify({'error': 'An error occurred while booking. Please try again later.'}), 500
    
@app.route('/agent_flights', methods=['GET'])
@login_required(role='agent')
def agent_my_flights():
    # Fetch flight data from the database
    query = """
        SELECT airline_name, flight_num, dep_a.name AS departure_airport, dep_a.city AS departure_city, departure_time, arr_a.name AS arrival_airport, arr_a.city AS arrival_city, arrival_time, COUNT(*) AS num_tickets
        FROM ticket NATURAL JOIN (flight f JOIN airport dep_a ON f.departure_airport = dep_a.name JOIN airport arr_a ON f.arrival_airport = arr_a.name)
        WHERE booking_agent_id = %s AND status = 'Upcoming'
        GROUP BY airline_name, flight_num, departure_airport, departure_time, arrival_airport, arrival_time
    """
    agent_email = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT booking_agent_id FROM booking_agent WHERE email = %s", (agent_email,))
    agent_id = cursor.fetchone()
    print(agent_id)

    cursor.execute(query, (agent_id,))
    agent_flights = cursor.fetchall()

    # Convert flight data to JSON format
    formatted_flights = []
    for flight in agent_flights:
        formatted_flight = {
            'airline_name': flight[0],
            'flight_num': flight[1],
            'departure_airport_code': flight[2],
            'departure_airport_city': flight[3],
            'departure_time': flight[4].strftime("%Y-%m-%d %H:%M:%S"),
            'arrival_airport_code': flight[5],
            'arrival_airport_city': flight[6],
            'arrival_time': flight[7].strftime("%Y-%m-%d %H:%M:%S"),
            'num_tickets': flight[8]
        }
        formatted_flights.append(formatted_flight)

    # Check if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # If it's an AJAX request, return JSON data
        return jsonify(formatted_flights)
    else:
        # If it's a regular HTTP request, render the template
        return render_template('a_view_my_flights.html', flights=agent_flights)
    
@app.route('/my_commission', methods=['GET'])
@login_required(role='agent')
def agent_commission():
    agent_email = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT booking_agent_id FROM booking_agent WHERE email = %s", (agent_email,))
    agent_id = cursor.fetchone()

    tot_commission_past_30 = """
        SELECT ROUND(SUM(price*0.10), 2) AS tot_commission 
        FROM ticket NATURAL JOIN flight 
        WHERE booking_agent_id = %s AND 
        date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
    """
    cursor.execute(tot_commission_past_30, (agent_id,))
    tot_commission = cursor.fetchone()[0]
    tot_commission = tot_commission

    tot_num_tickets_past_30 = """
        SELECT COUNT(ticket_id) AS num_tickets
        FROM ticket 
        WHERE booking_agent_id = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
    """
    cursor.execute(tot_num_tickets_past_30, (agent_id,))
    tot_tickets = cursor.fetchone()[0]

    avg_commission = tot_commission / tot_tickets if tot_tickets !=0 else 0
    avg_commission = round(avg_commission, 2)

    commission_data = {
        'tot_commission': tot_commission,
        'tot_tickets': tot_tickets,
        'avg_commission': avg_commission
    }

    cursor.close()
    return render_template('a_view_commission.html', commission_data=commission_data)

@app.route('/range_commission', methods=['POST'])
@login_required(role='agent')
def getRangeCommission():
    range_data = request.json
    agent_email = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT booking_agent_id FROM booking_agent WHERE email = %s", (agent_email,))
    agent_id = cursor.fetchone()

    start = range_data.get('start')
    end = range_data.get('end')

    query1 = """
        SELECT ROUND(SUM(price*0.10), 2) AS tot_commission 
        FROM ticket NATURAL JOIN flight 
        WHERE booking_agent_id = %s AND 
        date >= %s AND date <= %s
    """
    query2 = """
        SELECT COUNT(ticket_id) AS num_tickets
        FROM ticket 
        WHERE booking_agent_id = %s AND date >= %s AND date <= %s
    """

    cursor.execute(query1, (agent_id, start, end))
    commission = cursor.fetchone()[0]
    cursor.execute(query2, (agent_id, start, end))
    tickets = cursor.fetchone()[0]
    avg_commission = round(commission / tickets, 2)

    range_results = {
        'commission': str(commission),
        'tickets': tickets,
        'avg_commission': str(avg_commission)
    }
    print(range_results)
    cursor.close()
    return jsonify(range_results)

@app.route('/top_customers_tickets')
@login_required(role='agent')
def top_customers_tickets():
    query = """
    SELECT COUNT(ticket_id) as num_tickets, customer_email
    FROM ticket
    WHERE booking_agent_id = %s
    GROUP BY customer_email
    ORDER BY num_tickets DESC LIMIT 5
    """
    agent_email = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT booking_agent_id FROM booking_agent WHERE email = %s", (agent_email,))
    agent_id = cursor.fetchone()

    cursor.execute(query, (agent_id,))
    top_customers_tickets_data = cursor.fetchall()

    formatted_data = [{'customer_id': row[1], 'num_tickets': row[0]} for row in top_customers_tickets_data]
    return jsonify(formatted_data)

@app.route('/top_customers_commission')
@login_required(role='agent')
def top_customers_commission():
    query = """
        SELECT SUM(price*0.10) as commission, customer_email
        FROM ticket NATURAL JOIN flight
        WHERE booking_agent_id = %s
        GROUP BY customer_email
        ORDER BY commission DESC LIMIT 5
    """
    agent_email = session.get('username')
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT booking_agent_id FROM booking_agent WHERE email = %s", (agent_email,))
    agent_id = cursor.fetchone()

    cursor.execute(query, (agent_id,))
    top_customers_commission_data = cursor.fetchall()
    
    formatted_data = [{'customer_id': row[1], 'commission': row[0]} for row in top_customers_commission_data]
    print(formatted_data)
    return jsonify(formatted_data)

@app.route('/top_customers')
@login_required(role='agent')
def top_customers_page():
    return render_template('agent_top_customers.html')

@app.route('/staff_view_flights')
@login_required(role='staff')
def staff_my_flights():
    username = session.get('username')
    return render_template('s_view_flights.html', username=username)

@app.route('/s_default_view', methods=['GET'])
@login_required(role='staff')
def staff_default_flight_view():
    username = session.get('username')
    
    query = "SELECT airline_name FROM airline_staff WHERE username = %s"
    cursor = mysql.connection.cursor()
    cursor.execute(query, (username,))
    s_airline = cursor.fetchone()
    print(s_airline)

    current_date = datetime.now()
    future_date = current_date + timedelta(days=30)
    flight_query = "SELECT * FROM flight WHERE airline_name = %s AND departure_time BETWEEN %s AND %s"
    cursor.execute(flight_query, (s_airline[0], current_date, future_date))
    flights = cursor.fetchall()
    print(flights)
    cursor.close()
    return jsonify(flights)

@app.route('/s_advanced_view', methods=['GET'])
@login_required(role='staff')
def staff_advanced_flight_view():
    username = session.get('username')
    
    query = "SELECT airline_name FROM airline_staff WHERE username = %s"
    cursor = mysql.connection.cursor()
    cursor.execute(query, (username,))
    s_airline = cursor.fetchone()
    print(s_airline)

    departure_airport = request.args.get('deptAirport')
    arrival_airport = request.args.get('arrivalAirport')
    range_start = request.args.get('startDate')
    range_end = request.args.get('endDate')

    flight_query = "SELECT * FROM flight WHERE airline_name = %s AND departure_airport = %s AND arrival_airport = %s AND DATE(departure_time) BETWEEN %s AND %s"
    cursor.execute(flight_query, (s_airline[0], departure_airport, arrival_airport, range_start, range_end))
    flights = cursor.fetchall()
    print(flights)
    cursor.close()
    return jsonify(flights)

@app.route('/get_username', methods=['GET'])
def get_username():
    username = session.get('username')
    return jsonify({'username': username})

def check_permissions(username):
    cursor = mysql.connection.cursor()
    query = "SELECT permission FROM permission WHERE username = %s"
    cursor.execute(query, (username,))
    permissions = [row[0] for row in cursor.fetchall()] #might have multiple permissions

    isAdmin = 'Admin' in permissions
    isOperator = 'Operator' in permissions
    print(isAdmin, isOperator)

    return {'isAdmin': isAdmin, 'isOperator': isOperator}

@app.route('/viewCustomers', methods=['GET'])
@login_required(role='staff')
def view_customers():
    flight_number = request.args.get('flightNumber')
    airline_name = request.args.get('airlineName')

    cursor = mysql.connection.cursor()
    query = """
        SELECT customer_email
        FROM ticket
        WHERE flight_num = %s AND airline_name = %s
    """
    cursor.execute(query, (flight_number, airline_name))
    customers = cursor.fetchall()

    return render_template('view_customers.html', customers=customers)

def update_flight_status():
    query = "UPDATE flight SET status = %s"

@app.route('/changeFlightStatus', methods=['GET'])
@login_required(role='staff')
def change_flight_status():
    username = session.get('username')
    permissions = check_permissions(username)
    print(permissions)
    if permissions['isOperator']:
        return render_template('update_flight_status.html')
    else:
        return "You do not have permission to change flight status."
    
    
@app.route('/staff_success')
@login_required(role='staff')
def staff_success():
    message = request.args.get('message')
    return render_template('staff_success.html', message=message)

@app.route('/updateFlightStatus', methods=['POST'])
@login_required(role='staff')
def update_flight_status():
    username = session.get('username')
    permissions = check_permissions(username)
    print(permissions)
    if permissions['isOperator']:
        # Get the form data
        flight_number = request.form['flightNumber']
        new_status = request.form['newStatus']

        query = "SELECT airline_name FROM airline_staff WHERE username = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(query, (username,))
        airline = cursor.fetchone()[0]
        print(airline)
        print(flight_number)
        print(new_status)

        update_query = "UPDATE flight SET status = %s WHERE flight_num = %s AND airline_name = %s"
        
        try: 
            cursor.execute(update_query, (new_status, flight_number, airline))
            mysql.connection.commit()
            # Check if at least one row is updated (i.e. the flight number and airline match)
            if cursor.rowcount > 0:
                # Redirect to success page if update successful
                return redirect(url_for('staff_success', message="Flight status updated successfully."))
            else:
                # Render template with error message if no rows are updated
                return render_template('update_flight_status.html', message="Flight not found.")
        except Exception as e:
            return render_template('update_flight_status.html', message="Error updating flight status.")
        finally:
            cursor.close()

    else:
        # Redirect to an error page or handle unauthorized access
        return "Unauthorized access", 403  # Return a forbidden status code
    

@app.route('/create_flights')
@login_required(role='staff')
def create_flights():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        return render_template('create_flight.html')
    else:
        return "You do not have permission to create new flights."
    
@app.route('/new_flight', methods=['GET', 'POST'])
@login_required(role='staff')
def new_flight():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        flight_num = request.form['flight_num']
        airline_name = request.form['airline_name']
        airplane_id = request.form['airplane_id']
        departure_airport = request.form['departure_airport']
        departure_time = request.form['departure_time']
        arrival_airport = request.form['arrival_airport']
        arrival_time = request.form['arrival_time']
        price = request.form['price']
        status = request.form['status']

        departure_time = datetime.strptime(departure_time, "%Y-%m-%dT%H:%M")
        arrival_time = datetime.strptime(arrival_time, "%Y-%m-%dT%H:%M")

        query = "SELECT airline_name FROM airline_staff WHERE username = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(query, (username,))
        s_airline = cursor.fetchone()[0]

        if airline_name == s_airline:
            query = """
                INSERT INTO flight
                (flight_num, airline_name, airplane_id, departure_airport, departure_time, arrival_airport, arrival_time, price, status)
                VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            try:
                cursor.execute(query, (flight_num, airline_name, airplane_id, departure_airport, departure_time, arrival_airport, arrival_time, price, status))
                mysql.connection.commit()
                return redirect(url_for('staff_success', message="Flight added successfully."))
            except Exception as e:
                return render_template('create_flight.html', message="Error adding flight.")
            finally:
                cursor.close()
        else: 
            return render_template('create_flight.html', message="Invalid airline name.")
    else:
        return "You do not have permission to add a flight."

@app.route('/addAirplane')
@login_required(role='staff')
def add_airplane():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        return render_template('s_add_airplane.html')
    else:
        return "You do not have permission to add airplanes."
    
@app.route('/createAirplane', methods=['POST'])
@login_required(role='staff')
def create_airplane():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        airplane_id = request.form['airplaneID']
        seats = request.form['seats']

        query = "SELECT airline_name FROM airline_staff WHERE username = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(query, (username,))
        airline = cursor.fetchone()[0]

        query = """
            INSERT INTO airplane (id, airline_name, seats) 
            VALUES (%s, %s, %s)
        """

        try:
            cursor.execute(query, (airplane_id, airline, seats))
            mysql.connection.commit()
            return redirect(url_for('staff_success', message="Airplane added successfully."))
        except Exception as e:
            return render_template('s_add_airplane.html', message="Error adding airplane.")
        finally:
                cursor.close()
    else:
        return "You do not have permission to add a flight."

@app.route('/newPermission')
@login_required(role='staff')
def new_permission():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        return render_template('grant_new_permissions.html')
    else:
        return "You do not have permission to grant permissions."
    
@app.route('/grantPermission', methods=['POST'])
@login_required(role='staff')
def grant_permission():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        staff_username = request.form['staffUsername']
        permission = request.form['permission']

        query1 = "SELECT airline_name FROM airline_staff WHERE username = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(query1, (username,))
        user_airline = cursor.fetchone()[0]

        query2 = "SELECT airline_name FROM airline_staff WHERE username = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(query2, (staff_username,))
        new_staff_airline = cursor.fetchone()[0]

        if user_airline == new_staff_airline:

            query = """
                INSERT INTO permission (username, permission)
                VALUES (%s, %s)
            """

            try:
                cursor.execute(query, (staff_username, permission))
                mysql.connection.commit()
                return redirect(url_for('staff_success', message="Permission granted successfully."))
            except Exception as e:
                return render_template('grant_new_permissions.html', message="Error granting permission.")
            finally:
                    cursor.close()
        else: 
            return render_template('grant_new_permissions.html', message="Invalid staff username or permission.")
    else:
        return "You do not have permission to grant new permissions."

@app.route('/addBookingAgent')
@login_required(role='staff')
def add_booking_agent():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        return render_template('s_add_booking_agents.html')
    else:
        return "You do not have permission to add booking agents."

@app.route('/addAgent', methods=['POST'])
@login_required(role='staff')
def add_agent():
    username = session.get('username')
    permissions = check_permissions(username)

    if permissions['isAdmin']:
        agent_email = request.form['agentEmail']

        query = "SELECT airline_name FROM airline_staff WHERE username = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(query, (username,))
        airline = cursor.fetchone()[0]

        query = """
                INSERT INTO work_for (booking_agent_email, airline_name)
                VALUES (%s, %s)
            """
        try:
            cursor.execute(query, (agent_email, airline))
            mysql.connection.commit()
            return redirect(url_for('staff_success', message="Permission granted successfully."))
        except Exception as e:
            return render_template('s_add_booking_agents.html', message="Error adding booking agent.")
        finally:
            cursor.close()
    else:
        return "You do not have permission to grant new permissions."



@app.route('/mostFrequentCustomer')
@login_required(role='staff')
def most_freq_customer():
    username = session.get('username')
    query = "SELECT airline_name FROM airline_staff WHERE username = %s"
    cursor = mysql.connection.cursor()
    cursor.execute(query, (username,))
    airline = cursor.fetchone()[0]

    query = """
    SELECT customer_email
    FROM (
        SELECT customer_email, COUNT(ticket_id) AS ticket_count
        FROM ticket
        WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
        GROUP BY customer_email
    ) AS frequent_customers
    WHERE ticket_count = (
        SELECT MAX(ticket_count)
        FROM (
            SELECT COUNT(*) AS ticket_count
            FROM ticket
            WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
            GROUP BY customer_email
        ) AS ticket_counts
    )
    """
    cursor.execute(query, (airline, airline))
    top_customers = cursor.fetchall()
    cursor.close()

    return render_template('s_view_frequent_customers.html', top_customers=top_customers, airline=airline)


@app.route('/customer_flights', methods=['POST'])
@login_required(role='staff')
def customer_flights():
    customer_email = request.form.get('customer_email')
    airline = request.form.get('airline')

    # Query flights taken by the selected customer on the airline in the past year
    query = """
    SELECT flight_num, departure_airport, arrival_airport
    FROM flight NATURAL JOIN ticket t
    WHERE customer_email = %s AND airline_name = %s
    """
    cursor = mysql.connection.cursor()
    cursor.execute(query, (customer_email, airline))
    flights = cursor.fetchall()
    cursor.close()

    return render_template('customer_flights_by_airline.html', flights=flights, customer_email=customer_email)


@app.route('/topBookingAgents')
@login_required(role='staff')
def topBookingAgents():
    username = session.get('username')
    query = "SELECT airline_name FROM airline_staff WHERE username = %s"
    cursor = mysql.connection.cursor()
    cursor.execute(query, (username,))
    airline = cursor.fetchone()[0]

    query = """
        SELECT COUNT(email) 
        FROM booking_agent a JOIN work_for w ON a.email = w.booking_agent_email
        WHERE airline_name = %s
    """
    cursor.execute(query, (airline,))
    agent_count = cursor.fetchone()[0]
    if agent_count < 5:
        query1 = """
            SELECT email, booking_agent_id, COUNT(ticket_id) AS ticket_sales_past_month
            FROM ticket NATURAL JOIN booking_agent
            WHERE airline_name = %s
            AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)
            GROUP BY email, booking_agent_id
            ORDER BY ticket_sales_past_month DESC
            LIMIT 5
        """

        query2 ="""
            SELECT email, booking_agent_id, COUNT(ticket_id) AS ticket_sales_past_month
            FROM ticket NATURAL JOIN booking_agent
            WHERE airline_name = %s
            AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)
            GROUP BY email, booking_agent_id
            ORDER BY ticket_sales_past_month DESC
            LIMIT 5
        """

        query3 ="""
            SELECT email, booking_agent_id, SUM(price * 0.10) AS total_commission_last_year
            FROM ticket NATURAL JOIN flight NATURAL JOIN booking_agent
            WHERE airline_name = %s
            AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
            GROUP BY email, booking_agent_id
            ORDER BY total_commission_last_year DESC LIMIT 5;
        """
        cursor.execute(query1, (airline,))
        top_agents_past_month = cursor.fetchall()

        cursor.execute(query2, (airline,))
        top_agents_past_year = cursor.fetchall()

        cursor.execute(query3, (airline,))
        top_agents_commission = cursor.fetchall()

    else:
        query1 = """
            SELECT email, booking_agent_id,  COUNT(ticket_id) AS ticket_sales_past_month
            FROM ticket NATURAL JOIN booking_agent
            WHERE airline_name = %s
            AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)
            GROUP BY email, booking_agent_id
            HAVING ticket_sales_past_month = (
                SELECT ticket_sales_past_month
                FROM (
                    SELECT COUNT(ticket_id) AS ticket_sales_past_month
                    FROM ticket NATURAL JOIN booking_agent
                    WHERE airline_name = %s
                    AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)
                    GROUP BY email
                    ORDER BY ticket_sales_past_month DESC
                    LIMIT 1 OFFSET 4
                ) AS subquery
            )
            """

        query2 = """
            SELECT email,  booking_agent_id, COUNT(ticket_id) AS ticket_sales_past_year
            FROM ticket NATURAL JOIN booking_agent
            WHERE airline_name = %s
            AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
            GROUP BY email, booking_agent_id
            HAVING ticket_sales_past_year >= (
                SELECT ticket_sales_past_year
                FROM (
                    SELECT COUNT(ticket_id) AS ticket_sales_past_year
                    FROM ticket NATURAL JOIN booking_agent
                    WHERE airline_name = %s
                    AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
                    GROUP BY email
                    ORDER BY ticket_sales_past_year DESC
                    LIMIT 1 OFFSET 4
                ) AS subquery
            )
            """

        query3= """
            SELECT email, booking_agent_id, SUM(price * 0.10) AS total_commission_last_year
            FROM ticket NATURAL JOIN flight NATURAL JOIN booking_agent
            WHERE airline_name = %s
            AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
            GROUP BY email, booking_agent_id
            HAVING total_commission_last_year >= (
                SELECT total_commission_last_year
                FROM (
                    SELECT SUM(price * 0.10) AS total_commission_last_year
                    FROM ticket NATURAL JOIN flight NATURAL JOIN booking_agent
                    WHERE airline_name = %s
                    AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
                    GROUP BY email
                    ORDER BY total_commission_last_year DESC
                    LIMIT 1 OFFSET 4
                ) AS subquery
            )
            """

        cursor.execute(query1, (airline, airline))
        top_agents_past_month = cursor.fetchall()

        cursor.execute(query2, (airline, airline))
        top_agents_past_year = cursor.fetchall()

        cursor.execute(query3, (airline, airline))
        top_agents_commission = cursor.fetchall()

    cursor.close()
    return render_template('top_agents.html', airline=airline,
                           top_agents_past_month=top_agents_past_month,
                           top_agents_past_year=top_agents_past_year,
                           top_agents_commission=top_agents_commission)

@app.route('/getSalesReport')
@login_required(role='staff')
def get_sales_report():
    return render_template('s.make_sales_report.html')

@app.route('/ticketSalesReport', methods=['POST'])
@login_required(role='staff')
def ticket_sales_report():
    username = session.get('username')
    query = "SELECT airline_name FROM airline_staff WHERE username = %s"
    cursor = mysql.connection.cursor()
    cursor.execute(query, (username,))
    airline = cursor.fetchone()[0]

    date_range = request.form.get('date_range')
    
    if date_range == 'past_month':
        query = """
            SELECT COUNT(ticket_id) AS num_tickets
            FROM ticket
            WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)
        """
        cursor.execute(query, (airline,))
        num_tickets = cursor.fetchone()[0]
    
    elif date_range == 'past_year':
        query = """
            SELECT COUNT(ticket_id) AS num_tickets
            FROM ticket
            WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
        """
        cursor.execute(query, (airline,))
        num_tickets = cursor.fetchone()[0]
    
    else:
        start_date = request.form.get('custom_start_date')
        end_date = request.form.get('custom_end_date')
        query = """
            SELECT COUNT(ticket_id) AS num_tickets
            FROM ticket
            WHERE airline_name = %s AND date BETWEEN %s AND %s)
        """
        cursor.execute(query, (airline, start_date, end_date))
        num_tickets = cursor.fetchone()[0]
    cursor.close()

    return render_template('s_view_reports.html', num_tickets=num_tickets)

@app.route('/getRevenueInfo')
@login_required(role='staff')
def revenueComparison():
    username = session.get('username')
    query = "SELECT airline_name FROM airline_staff WHERE username = %s"
    cursor = mysql.connection.cursor()
    cursor.execute(query, (username,))
    airline = cursor.fetchone()[0]
    query1 = """
        SELECT SUM(price) as year_revenue
        FROM ticket NATURAL JOIN flight
        WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
    """
    cursor.execute(query1, (airline,))
    past_year_revenue = cursor.fetchone()[0]

    query2 = """
        SELECT SUM(price) as month_revenue
        FROM ticket NATURAL JOIN flight
        WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH)
    """
    cursor.execute(query2, (airline,))
    past_month_revenue = cursor.fetchone()[0]

    query3 = """
        SELECT SUM(price) as year_revenue
        FROM ticket NATURAL JOIN flight
        WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR) 
        AND booking_agent_id IS NULL
    """
    cursor.execute(query3, (airline,))
    past_year_direct_sales = cursor.fetchone()[0]

    query4 = """
        SELECT SUM(price) as month_revenue
        FROM ticket NATURAL JOIN flight
        WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH) 
        AND booking_agent_id IS NULL
    """
    cursor.execute(query4, (airline,))
    past_month_direct_sales = cursor.fetchone()[0]

    query5 = """
        SELECT SUM(price) as year_revenue
        FROM ticket NATURAL JOIN flight
        WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR) 
        AND booking_agent_id IS NOT NULL
    """
    cursor.execute(query5, (airline,))
    past_year_indirect_sales = cursor.fetchone()[0]

    query6 = """
        SELECT SUM(price) as month_revenue
        FROM ticket NATURAL JOIN flight
        WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 MONTH) 
        AND booking_agent_id IS NOT NULL
    """
    cursor.execute(query6, (airline,))
    past_month_indirect_sales = cursor.fetchone()[0]
    cursor.close()

    return render_template('s_revenue.html', 
                           past_year_revenue=past_year_revenue,
                           past_month_revenue=past_month_revenue,
                           past_year_direct_sales=past_year_direct_sales,
                           past_month_direct_sales=past_month_direct_sales,
                           past_year_indirect_sales=past_year_indirect_sales,
                           past_month_indirect_sales=past_month_indirect_sales)


@app.route('/getTopDestinations')
@login_required(role='staff')
def get_top_destinations():
    username = session.get('username')
    query = "SELECT airline_name FROM airline_staff WHERE username = %s"
    cursor = mysql.connection.cursor()
    cursor.execute(query, (username,))
    airline = cursor.fetchone()[0]

    query_year = """
        SELECT t1.arrival_airport, COUNT(*) AS num_tickets
        FROM (
            SELECT arrival_airport, COUNT(*) AS num_tickets
            FROM ticket NATURAL JOIN flight
            WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
            GROUP BY arrival_airport
        ) AS t1
        JOIN (
            SELECT arrival_airport, COUNT(*) AS third_num_tickets
            FROM (
                SELECT arrival_airport, COUNT(*) AS num_tickets
                FROM ticket NATURAL JOIN flight
                WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 1 YEAR)
                GROUP BY arrival_airport
                ORDER BY num_tickets DESC
                LIMIT 2, 1
            ) AS t2
        ) AS t3
        ON t1.arrival_airport = t3.arrival_airport
        WHERE t1.num_tickets >= t3.third_num_tickets
        ORDER BY t1.num_tickets DESC
    """
    cursor.execute(query_year, (airline, airline))
    top_dest_year = cursor.fetchall()

    query_3_months = """
        SELECT t1.arrival_airport, COUNT(*) AS num_tickets
        FROM (
            SELECT arrival_airport, COUNT(*) AS num_tickets
            FROM ticket NATURAL JOIN flight
            WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
            GROUP BY arrival_airport
        ) AS t1
        JOIN (
            SELECT arrival_airport, COUNT(*) AS third_num_tickets
            FROM (
                SELECT arrival_airport, COUNT(*) AS num_tickets
                FROM ticket NATURAL JOIN flight
                WHERE airline_name = %s AND date >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
                GROUP BY arrival_airport
                ORDER BY num_tickets DESC
                LIMIT 2, 1
            ) AS t2
        ) AS t3
        ON t1.arrival_airport = t3.arrival_airport
        WHERE t1.num_tickets >= t3.third_num_tickets
        ORDER BY t1.num_tickets DESC
    """
    cursor.execute(query_3_months, (airline, airline))
    top_dest_3_months = cursor.fetchall()
    cursor.close()

    return render_template('s_view_top_dest.html', top_dest_year=top_dest_year, top_dest_3_months=top_dest_3_months)




"""
# Define a route to display upcoming flights
@app.route('/')
def upcoming_flights():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT flight_num, airline_name, departure_airport, departure_time, arrival_airport, arrival_time FROM flight WHERE status = 'Upcoming'")
    flights = cursor.fetchall()
    cursor.close()
    return render_template('upcoming_flights.html', flights=flights)
"""

if __name__ == '__main__':
    app.run('127.0.0.1', 5000, debug=True)
