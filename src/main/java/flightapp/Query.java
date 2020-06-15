package flightapp;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.naming.spi.DirStateFactory.Result;

/**
 * Runs queries against a back-end database
 */
public class Query {
    // DB Connection
    private Connection conn;

    // Password hashing parameter constants
    private static final int HASH_STRENGTH = 65536;
    private static final int KEY_LENGTH = 128;

    // Canned queries
    private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
    private PreparedStatement checkFlightCapacityStatement;

    // For check dangling
    private static final String TRANCOUNT_SQL = "SELECT @@TRANCOUNT AS tran_count";
    private PreparedStatement tranCountStatement;

    // Clear table
    private static final String CLEARTABLE = "TRUNCATE TABLE Reservations; DELETE FROM Users; ";
    private PreparedStatement clearTableStatement;

    // Checking Username
    private static final String CHECKUSER = "SELECT * FROM Users WHERE username = ?";
    private PreparedStatement checkUserStatement;

    // Creating Users
    private static final String CREATEUSER = "INSERT INTO Users VALUES (?, ?, ?, ?)";
    private PreparedStatement createUserStatement;

    // Search for direct flights
    private static final String SEARCH_DIRECT_FLIGHT = "SELECT TOP (?) " +
    "f.fid, f.day_of_month, f.carrier_id, f.flight_num, " +
    "f.origin_city, f.dest_city, f.actual_time, f.capacity, f.price " +
    "FROM Flights AS f " +
    "WHERE f.origin_city = ? AND f.dest_city = ? " +
        "AND f.day_of_month = ? AND f.canceled = 0 " +
    "ORDER BY f.actual_time, f.fid ";
    private PreparedStatement searchDirectStatement;

    // Search for indirect flights
    private static final String SEARCH_INDIRECT_FLIGHT = "SELECT TOP (?) " + 
    "f1.fid, f1.day_of_month, f1.carrier_id, f1.flight_num, " + 
    "f1.origin_city, f1.dest_city, f1.actual_time, f1.capacity, f1.price, " +
    "f2.fid, f2.day_of_month, f2.carrier_id, f2.flight_num, " + 
    "f2.origin_city, f2.dest_city, f2.actual_time, f2.capacity, f2.price " +
    "FROM Flights AS f1, Flights AS f2 " +
    "WHERE f1.dest_city = f2.origin_city AND f1.day_of_month = f2.day_of_month " + 
        "AND f1.fid != f2.fid AND f1.origin_city = ? AND f2.dest_city = ? " + 
        "AND f1.day_of_month = ? AND f1.canceled = 0 AND f2.canceled = 0 " +
    " ORDER BY (f1.actual_time + f2.actual_time), f1.fid, f2.fid ";
    private PreparedStatement searchIndirectStatement;

    // get the reservation id with username and date
    private static final String RESERVATION_ID = "SELECT r.rid " +
    "FROM Reservations AS r " + 
    "WHERE r.username = ? AND r.date = ? AND r.cancelled = 0 ";
    private PreparedStatement getReservationId;

    // Book a reservation
    private static final String BOOK_RESERVATION = "INSERT INTO Reservations (username, date, flight1id, flight2id) " +
    "VALUES (?, ?, ?, ?) ";
    private PreparedStatement bookReservation;

    // get reservation price (with rid)
    private static final String GET_RESERVATION_PRICE = "SELECT F1.price + ISNULL(F2.price, 0) " +
    "FROM Reservations AS R LEFT OUTER JOIN Flights AS F1 ON R.flight1id = F1.fid " +
    "LEFT OUTER JOIN Flights AS F2 ON R.flight2id = F2.fid " +
    "WHERE R.rid = ? AND R.paid = 0 ";
    private PreparedStatement getReservationPrice;

    // get user balance (with username)
    private static final String GET_USER_BALANCE = "SELECT u.balance FROM Users AS u WHERE u.username = ? ";
    private PreparedStatement getUserBalance;

    // pay reservation
    private static final String PAY_RESERVATION = "UPDATE Reservations SET paid = 1 " + 
    "WHERE rid = ? AND cancelled = 0 AND paid = 0 ";
    private PreparedStatement payReservation;

    // update user balance
    private static final String UPDATE_USER_BALANCE = "UPDATE Users SET balance = ? WHERE username = ?";
    private PreparedStatement updateUserBalance;

    // get all reservation (with username)
    private static final String GET_ALL_RESERVATION = "SELECT R.rid, R.paid, R.flight1id, R.flight2id " +
    "FROM Reservations AS R " +
    "WHERE R.username = ? AND cancelled = 0 " +
    "ORDER BY R.rid ";
    private PreparedStatement getAllReservation;

    // get flight info (with fid)
    private static final String GET_FLIGHT_INFO = "SELECT f.fid, f.day_of_month, f.carrier_id, f.flight_num, " +
    "f.origin_city, f.dest_city, f.actual_time, f.capacity, f.price " +
    "FROM Flights AS f " +
    "WHERE f.fid = ? ";
    private PreparedStatement getFlightInfo;

    // check flight has space (with fid)
    private static final String NUMBER_SEAT_TAKEN = "SELECT COUNT(*) " +
    "FROM Reservations AS r " +
    "WHERE r.flight1id = ? OR r.flight2id = ? ";
    private PreparedStatement numberSeatTaken;

    // cancel reservation
    private static final String CANCEL_RESERVATION = "UPDATE Reservations SET cancelled = 1 WHERE rid = ? AND cancelled = 0";
    private PreparedStatement cancelReservation;

    // check reservation status
    private static final String CHECK_RESERVATION_STATUS = "SELECT R.cancelled, R.paid FROM Reservations AS R WHERE R.rid = ? ";
    private PreparedStatement checkReservationStatus;

    // Set the default login status
    private String loginedUser = null;

    // search resutl
    private ArrayList<Itinerary> searchResults = new ArrayList<>();

    static boolean lock = false;

    public Query() throws SQLException, IOException {
        this(null, null, null, null);
    }

    protected Query(String serverURL, String dbName, String adminName, String password)
        throws SQLException, IOException {
        conn = serverURL == null ? openConnectionFromDbConn()
            : openConnectionFromCredential(serverURL, dbName, adminName, password);

        prepareStatements();
    }

    /**
     * Return a connecion by using dbconn.properties file
     *
     * @throws SQLException
     * @throws IOException
     */
    public static Connection openConnectionFromDbConn() throws SQLException, IOException {
        // Connect to the database with the provided connection configuration
        Properties configProps = new Properties();
        configProps.load(new FileInputStream("dbconn.properties"));
        String serverURL = configProps.getProperty("flightapp.server_url");
        String dbName = configProps.getProperty("flightapp.database_name");
        String adminName = configProps.getProperty("flightapp.username");
        String password = configProps.getProperty("flightapp.password");
        return openConnectionFromCredential(serverURL, dbName, adminName, password);
    }

    /**
     * Return a connecion by using the provided parameter.
     *
     * @param serverURL example: example.database.widows.net
     * @param dbName    database name
     * @param adminName username to login server
     * @param password  password to login server
     *
     * @throws SQLException
     */
    protected static Connection openConnectionFromCredential(String serverURL, String dbName,
        String adminName, String password) throws SQLException {
        String connectionUrl =
            String.format("jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s", serverURL,
                dbName, adminName, password);
        Connection conn = DriverManager.getConnection(connectionUrl);

        // By default, automatically commit after each statement
        conn.setAutoCommit(true);

        // By default, set the transaction isolation level to serializable
        conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

        return conn;
    }

    /**
     * Get underlying connection
     */
    public Connection getConnection() {
        return conn;
    }

    /**
     * Closes the application-to-database connection
     */
    public void closeConnection() throws SQLException {
        conn.close();
    }

    /**
     * Clear the data in any custom tables created.
     * 
     * WARNING! Do not drop any tables and do not clear the flights table.
     */
    public void clearTables() {
        try {
            prepareStatements();
            clearTableStatement.executeUpdate();
            clearTableStatement.closeOnCompletion();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
    * prepare all the SQL statements in this method.
    */
    private void prepareStatements() throws SQLException {
        checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
        tranCountStatement = conn.prepareStatement(TRANCOUNT_SQL);
        checkUserStatement = conn.prepareStatement(CHECKUSER);
        createUserStatement = conn.prepareStatement(CREATEUSER);
        clearTableStatement = conn.prepareStatement(CLEARTABLE);
        searchDirectStatement = conn.prepareStatement(SEARCH_DIRECT_FLIGHT);
        searchIndirectStatement = conn.prepareStatement(SEARCH_INDIRECT_FLIGHT);
        getReservationId = conn.prepareStatement(RESERVATION_ID);
        bookReservation = conn.prepareStatement(BOOK_RESERVATION, Statement.RETURN_GENERATED_KEYS);
        getUserBalance = conn.prepareStatement(GET_USER_BALANCE);
        payReservation = conn.prepareStatement(PAY_RESERVATION);
        updateUserBalance = conn.prepareStatement(UPDATE_USER_BALANCE);
        getReservationPrice = conn.prepareStatement(GET_RESERVATION_PRICE);
        getAllReservation = conn.prepareStatement(GET_ALL_RESERVATION);
        getFlightInfo = conn.prepareStatement(GET_FLIGHT_INFO);
        numberSeatTaken = conn.prepareStatement(NUMBER_SEAT_TAKEN);
        cancelReservation = conn.prepareStatement(CANCEL_RESERVATION);
        checkReservationStatus = conn.prepareStatement(CHECK_RESERVATION_STATUS);
    }

    /**
     * Takes a user's username and password and attempts to log the user in.
     *
     * @param username user's username
     * @param password user's password
     *
     * @return If someone has already logged in, then return "User already logged in\n" For all other
     *         errors, return "Login failed\n". Otherwise, return "Logged in as [username]\n".
     */
    public String transaction_login(String username, String password) {
        // check login status
        if(loginedUser != null) {
            return "User already logged in\n";
        }
        // Check input viladation
        if (username == null ||username.length() >20 || password.length() > 20) {
            return "Login failed\n";
        }
        try {
            // convert Usernames
            String theUsername = username.toLowerCase();
            // check user 
            conn.setAutoCommit(false);
            prepareStatements();
            checkUserStatement.clearParameters();
            checkUserStatement.setString(1, theUsername);
            ResultSet result = checkUserStatement.executeQuery();
            if(result.next()) { //retrieve user info
                byte[] salt = result.getBytes("salt");
                byte[] hash = result.getBytes("hash");
                // decrypt password with salt
                byte[] theHash = decrypt(password, salt);
                // verify user password
                if(Arrays.equals(theHash, hash)) {
                    loginedUser = username;
                    searchResults.clear();
                    return "Logged in as " + username + "\n";
                }else {
                    return "Login failed\n";
                }
            }else {
                return "Login failed\n";
            }
        } catch(SQLException e) {
            try {
                conn.rollback();
                return "Login failed\n";
            } catch (SQLException ex) {
            }
        } finally {
            try {
                conn.setAutoCommit(true);
            } catch (SQLException e) {
            }
        }
        return "Login failed\n";
    }

    /**
     * Decrypt the user password with corresponding salt
     * 
     * @param password user's password
     * @param salt     corresponding user's salt
     * 
     * @return the decrypted hash
     */
    private byte[] decrypt(String password, byte[] salt) {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);
        // Generate the hash
        SecretKeyFactory factory = null;
        byte[] hash = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            hash = factory.generateSecret(spec).getEncoded();
            return hash;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalStateException();
        }
    }

    /**
     * Implement the create user function.
     *
     * @param username   new user's username. User names are unique the system.
     * @param password   new user's password.
     * @param initAmount initial amount to deposit into the user's account, should be >= 0 (failure
     *                   otherwise).
     *
     * @return either "Created user {@code username}\n" or "Failed to create user\n" if failed.
     */
    public String transaction_createCustomer(String username, String password, int initAmount) {
        // Check input viladation
        if(initAmount < 0 || username == null || username.length() >20 || password.length() > 20){
        return "Failed to create user\n";
        }

        try {
        //convert Usernames
            String theUsername = username.toLowerCase(); 
            try{
                //check username valiadation
                prepareStatements();
                checkUserStatement.clearParameters();
                checkUserStatement.setString(1, theUsername);
                ResultSet result = checkUserStatement.executeQuery();
                if(result.next() == true){ //username is already existed
                    return "Failed to create user\n";
                } else { //username valid
                    // Encrypy the password:
                    byte[][] encrypied = encrypyPassword(password);
                    // Store user info to the Users table
                    prepareStatements();
                    createUserStatement.clearParameters();
                    createUserStatement.setString(1, theUsername);
                    createUserStatement.setBytes(2, encrypied[1]);
                    createUserStatement.setBytes(3, encrypied[0]);
                    createUserStatement.setInt(4, initAmount);
                    createUserStatement.executeUpdate();
                    return "Created user " + username + "\n";
                }
            } catch(Exception e) {
                return "Failed to create user\n";
            }
        } finally {
            checkDanglingTransaction();
        }
    }

    /**
     * encrypy the passward
     * 
     * @param password
     * @return a 2D dyte array which contain salt and hash
     */
    private byte[][] encrypyPassword(String password) {
        // Generate a random cryptographic salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        // Specify the hash parameters
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);
        // Generate the hash
        SecretKeyFactory factory = null;
        byte[] hash = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            hash = factory.generateSecret(spec).getEncoded();
            return new byte[][]{salt, hash};
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalStateException();
        }
    };

    /**
     * Implement the search function.
     *
     * Searches for flights from the given origin city to the given destination city, on the given day
     * of the month. If {@code directFlight} is true, it only searches for direct flights, otherwise
     * is searches for direct flights and flights with two "hops." Only searches for up to the number
     * of itineraries given by {@code numberOfItineraries}.
     *
     * The results are sorted based on total flight time.
     *
     * @param originCity
     * @param destinationCity
     * @param directFlight        if true, then only search for direct flights, otherwise include
     *                            indirect flights as well
     * @param dayOfMonth
     * @param numberOfItineraries number of itineraries to return
     *
     * @return If no itineraries were found, return "No flights match your selection\n". If an error
     *         occurs, then return "Failed to search\n".
     *
     *         Otherwise, the sorted itineraries printed in the following format:
     *
     *         Itinerary [itinerary number]: [number of flights] flight(s), [total flight time]
     *         minutes\n [first flight in itinerary]\n ... [last flight in itinerary]\n
     *
     *         Each flight should be printed using the same format as in the {@code Flight} class.
     *         Itinerary numbers in each search should always start from 0 and increase by 1.
     *
     * @see Flight#toString()
     */
    public String transaction_search(String originCity, String destinationCity, boolean directFlight,
        int dayOfMonth, int numberOfItineraries) {
        // empty search results when initiate a new search
        searchResults.clear();
        try {
            // search for direct flights
            prepareStatements();
            searchDirectStatement.clearParameters();
            searchDirectStatement.setInt(1, numberOfItineraries);
            searchDirectStatement.setString(2, originCity);
            searchDirectStatement.setString(3, destinationCity);
            searchDirectStatement.setInt(4, dayOfMonth);
            ResultSet directresult = searchDirectStatement.executeQuery();
            while(directresult.next()) {
                searchResults.add(flightToItinerary(directresult, true));
            }
            // search for indirect flights
            if(!directFlight && numberOfItineraries > searchResults.size()) {
                prepareStatements();
                searchIndirectStatement.clearParameters();
                searchIndirectStatement.setInt(1, (numberOfItineraries - searchResults.size()));
                searchIndirectStatement.setString(2, originCity);
                searchIndirectStatement.setString(3, destinationCity);
                searchIndirectStatement.setInt(4, dayOfMonth);
                ResultSet inDirectresult = searchIndirectStatement.executeQuery();
                while(inDirectresult.next()) {
                    searchResults.add(flightToItinerary(inDirectresult, false));
                }
            }
        }catch (Exception e) {
            searchResults.clear();
            return "Failed to search\n";
        }
        if (searchResults.isEmpty()) {
            return "No flights match your selection\n";
        }
        searchResults.sort(Itinerary::compareTo);
        StringBuilder output = new StringBuilder();
            for (int i = 0; i < searchResults.size(); i++) {
            output.append(searchResults.get(i).toString(i));
        }
        return output.toString();
    }
    /**
     * Store the flight information that read from database into each flight object
     * 
     * @param set the resultset contain the flight information
     * @param directFlight a boolean value to determain where it is a direct flight
     * @return a flight object that contain all the information.
     * @throws SQLException
     */
    private Flight storeFlightInfo(ResultSet set, boolean directFlight) throws SQLException {
        int startIndex;
        Flight f = new Flight();
        if(directFlight) { // if direct flight read from 1 to 9
            startIndex = 1;
        }else { // if indirect flight read from 10 to 19
            startIndex = 10;
        }
        f.fid = set.getInt(startIndex);
        f.dayOfMonth = set.getInt(startIndex + 1);
        f.carrierId = set.getString(startIndex + 2);
        f.flightNum = set.getString(startIndex + 3);
        f.originCity = set.getString(startIndex + 4);
        f.destCity = set.getString(startIndex + 5);
        f.time = set.getInt(startIndex + 6);
        f.capacity = set.getInt(startIndex + 7);
        f.price = set.getInt(startIndex + 8);
        return f;
    }

    /**
     * Assign flight to each itinerary
     * 
     * @param set the result set contain the flight information
     * @param directFlight  boolean value to determain where it is a direct flight
     * @return a itinerary object that contain flight and flight information.
     * @throws SQLException
     */
    private Itinerary flightToItinerary(ResultSet set, boolean directFlight) throws SQLException {
        Itinerary it = new Itinerary();
        if(directFlight){
            it.flight1 = storeFlightInfo(set, true);
        }else {
            it.flight1 = storeFlightInfo(set, true);
            it.flight2 = storeFlightInfo(set, false);
        }
        return it;
    }

    /**
        * Implements the book itinerary function.
        *
        * @param itineraryId ID of the itinerary to book. This must be one that is returned by search in
        *                    the current session.
        *
        * @return If the user is not logged in, then return "Cannot book reservations, not logged in\n".
        *         If the user is trying to book an itinerary with an invalid ID or without having done a
        *         search, then return "No such itinerary {@code itineraryId}\n". If the user already has
        *         a reservation on the same day as the one that they are trying to book now, then return
        *         "You cannot book two flights in the same day\n". For all other errors, return "Booking
        *         failed\n".
        *
        *         And if booking succeeded, return "Booked flight(s), reservation ID: [reservationId]\n"
        *         where reservationId is a unique number in the reservation system that starts from 1 and
        *         increments by 1 each time a successful reservation is made by any user in the system.
        */
    public String transaction_book(int itineraryId) {
        // Check login status
        if(loginedUser == null) {
            return "Cannot book reservations, not logged in\n";
        }
        // Check itineraryID validation
        if(itineraryId >= searchResults.size() || searchResults.isEmpty() || itineraryId < 0) {
            return "No such itinerary "+ itineraryId +"\n";
        }
        // get itinerary from the search result
        Itinerary it = searchResults.get(itineraryId);
        int theDate = it.flight1.dayOfMonth;
        try {
            // lock the process while one user is booking
            while(lock) {
                Thread.sleep(1000);
            }
            lock = true;
            conn.setAutoCommit(false);
            // Check existence reservation
            if(getReservationId(loginedUser, theDate).next()) {
                return "You cannot book two flights in the same day\n";
            }
            // Book reservation
            // check if the flgiht has space
            if(checkFlightHasSpace(it.flight1.fid) && (it.directFlight() || checkFlightHasSpace(it.flight2.fid))) {
                bookReservation.clearParameters();
                bookReservation.setString(1, loginedUser);
                bookReservation.setInt(2, theDate);
                bookReservation.setInt(3, it.flight1.fid);
                if(it.directFlight()) {
                    bookReservation.setNull(4, Types.INTEGER);
                }else {
                    bookReservation.setInt(4, it.flight2.fid);
                }
                // update the reservation table
                bookReservation.executeUpdate();
                // retrieve the reservation id
                ResultSet resutl = getReservationId(loginedUser, theDate);
                if(resutl.next()) {
                    int reservationId = resutl.getInt("rid");
                    return "Booked flight(s), reservation ID: " + reservationId + "\n";
                }  
            }      
        } catch (Exception e) {
            try {
                lock = false;
                conn.setAutoCommit(true);
                e.printStackTrace();
            } catch (SQLException ex) {
                ex.printStackTrace();
                return ex.getMessage();
            }
        } finally {
            try {
                lock = false;
                conn.commit();
                conn.setAutoCommit(true);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        } 
        return "Booking failed\n";
    }

    private boolean checkFlightHasSpace(int fid) throws SQLException {
        int capacity = checkFlightCapacity(fid);
        int seatTaken = 0;
        prepareStatements();
        numberSeatTaken.clearParameters();
        numberSeatTaken.setInt(1, fid);
        numberSeatTaken.setInt(2, fid);
        ResultSet result = numberSeatTaken.executeQuery();
        if (result.next()) {
            seatTaken = result.getInt(1);
        }
        return capacity - seatTaken > 0;
    }

    private ResultSet getReservationId(String username, int date) throws SQLException {
        prepareStatements();
        getReservationId.clearParameters();
        getReservationId.setString(1, username);
        getReservationId.setInt(2, date);
        return getReservationId.executeQuery();
    }

    /**
     * Implements the pay function.
     *
     * @param reservationId the reservation to pay for.
     *
     * @return If no user has logged in, then return "Cannot pay, not logged in\n" If the reservation
     *         is not found / not under the logged in user's name, then return "Cannot find unpaid
     *         reservation [reservationId] under user: [username]\n" If the user does not have enough
     *         money in their account, then return "User has only [balance] in account but itinerary
     *         costs [cost]\n" For all other errors, return "Failed to pay for reservation
     *         [reservationId]\n"
     *
     *         If successful, return "Paid reservation: [reservationId] remaining balance:
     *         [balance]\n" where [balance] is the remaining balance in the user's account.
     */
    public String transaction_pay(int reservationId) {
        if(loginedUser == null) {
            return "Cannot pay, not logged in\n";
        }

        try {
            int reservationPrice;
            try {
                reservationPrice = getReservationPrice(reservationId);
            } catch (Exception e) {
                return "Cannot find unpaid reservation " + reservationId + " under user: " + loginedUser + "\n";
            }
            conn.setAutoCommit(false);
            int userBalance = getUserBalance(loginedUser);
            if(userBalance > reservationPrice) {
                int newBalance = userBalance - reservationPrice;
                prepareStatements();
                // pay reservation
                payReservation.clearParameters();
                payReservation.setInt(1, reservationId);
                payReservation.executeUpdate();
                // update user balance
                updateUserBalance.clearParameters();
                updateUserBalance.setInt(1, newBalance);
                updateUserBalance.setString(2, loginedUser);
                updateUserBalance.executeUpdate();
                conn.commit();
                return "Paid reservation: " + reservationId + " remaining balance: " + newBalance + "\n";
            }else {
                return "User has only " + userBalance + " in account but itinerary costs " + reservationPrice + "\n";
            }
        }catch(SQLException e) {
            try {
                conn.rollback();
            } catch (SQLException ex) {
            }
        }
        finally {
            try {
                conn.setAutoCommit(true);
            } catch (SQLException e) {
            }
        }
        return "Failed to pay for reservation " + reservationId + "\n";
    }

    private int getReservationPrice(int reservationId) throws SQLException {
        prepareStatements();
        getReservationPrice.clearParameters();
        getReservationPrice.setInt(1, reservationId);
        ResultSet result = getReservationPrice.executeQuery();
        if (result.next()) {
            return result.getInt(1);
        }else {
            throw new SQLException("Failed to get reservation price.");
        }
    }

    private int getUserBalance(String username) throws SQLException {
        prepareStatements();
        getUserBalance.clearParameters();
        getUserBalance.setString(1, username);
        ResultSet result = getUserBalance.executeQuery();
        if(result.next()) {
            return result.getInt(1);
        }else {
            throw new SQLException("Failed to get the balance of the current user.");
        }
    }

    /**
     * Implements the reservations function.
     *
     * @return If no user has logged in, then return "Cannot view reservations, not logged in\n" If
     *         the user has no reservations, then return "No reservations found\n" For all other
     *         errors, return "Failed to retrieve reservations\n"
     *
     *         Otherwise return the reservations in the following format:
     *
     *         Reservation [reservation ID] paid: [true or false]:\n 
     *         [flight 1 under the reservation]\n 
     *         [flight 2 under the reservation]\n 
     *         Reservation [reservation ID] paid: [true or false]:\n 
     *         [flight 1 under the reservation]\n 
     *         [flight 2 under the reservation]\n 
     *         ...
     *
     *         Each flight should be printed using the same format as in the {@code Flight} class.
     *
     * @see Flight#toString()
     */
    public String transaction_reservations() {
        if(loginedUser == null) {
            return "Cannot view reservations, not logged in\n";
        }
        try {
            conn.setAutoCommit(false);
            // get reservation base on username
            prepareStatements();
            getAllReservation.clearParameters();
            getAllReservation.setString(1, loginedUser);
            ResultSet result = getAllReservation.executeQuery();
            if(result.next()) {
                StringBuffer sb = new StringBuffer();
                do { // retrieve the ueser info row by row
                    int rid = result.getInt("rid");
                    boolean paid = result.getInt("paid") == 1;
                    int fid1 = result.getInt("flight1id");
                    int fid2 = result.getInt("flight2id");
                    boolean direct = result.wasNull();
                    Flight flight1 = retrieveFlightInfo(fid1);
                    // append to the stringbuffer
                    sb.append("Reservation ").append(rid).append(" paid: ").append(paid).append(":\n");
                    sb.append(flight1);
                    if(!direct) {
                        Flight flight2 = retrieveFlightInfo(fid2);
                        sb.append(flight2);
                    }
                } while (result.next());
                conn.commit();
                return sb.toString();
            }
        } catch (Exception e) {
            try {
                String m = e.getMessage();
                e.printStackTrace();
                conn.rollback();
                conn.setAutoCommit(true);
                return "Failed to retrieve reservations\n" + m + "\n";
            } catch (SQLException ex) {
                ex.printStackTrace();
            }
        }
        finally {
            try {
                conn.setAutoCommit(true);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return "No reservations found\n";
    }

    private Flight retrieveFlightInfo(int fid) throws SQLException {
        try {
            prepareStatements();
            getFlightInfo.setInt(1, fid);
            ResultSet result = getFlightInfo.executeQuery();
            if(result.next()) {
                return storeFlightInfo(result, true);
            }else{
                throw new SQLException("Failed to retrieve the flight info.");
            }
        } catch (Exception e) {
            String m = e.getMessage();
            throw new SQLException("Failed to retrieve the flight info." + m);
        }
    }

    /**
     * Implements the cancel operation.
     *
     * @param reservationId the reservation ID to cancel
     *
     * @return If no user has logged in, then return "Cannot cancel reservations, not logged in\n" For
     *         all other errors, return "Failed to cancel reservation [reservationId]\n"
     *
     *         If successful, return "Canceled reservation [reservationId]\n"
     *
     *         Even though a reservation has been canceled, its ID should not be reused by the system.
     */
    public String transaction_cancel(int reservationId) {
        if(loginedUser == null) {
            return "Cannot cancel reservations, not logged in\n";
        }
        try {
            boolean paid = false;
            conn.setAutoCommit(false);
            // check reservation status
            prepareStatements();
            checkReservationStatus.clearParameters();
            checkReservationStatus.setInt(1, reservationId);
            ResultSet check = checkReservationStatus.executeQuery();
            if(check.next()) {
                if(check.getInt(1) == 1) {
                    conn.commit();
                    return "Failed to cancel reservation " + reservationId + "\n";
                }
                paid = (check.getInt(2) == 1);
            }
            // cancel the reservation
            cancelReservation.clearParameters();
            cancelReservation.setInt(1, reservationId);
            cancelReservation.executeUpdate();
            if(paid){ // refund the user
                getReservationPrice.clearParameters();
                getReservationPrice.setInt(1, reservationId);
                ResultSet result = getReservationPrice.executeQuery();
                if(result.next()) { 
                    int price = result.getInt(1);
                    int balance = getUserBalance(loginedUser);
                    updateUserBalance.clearParameters();
                    updateUserBalance.setInt(1, balance + price);
                    updateUserBalance.setString(2, loginedUser);
                    updateUserBalance.executeUpdate();
                    conn.commit();
                }
            }
            return "Canceled reservation " + reservationId + "\n";
            
        } catch (SQLException e) {
            try {
                e.printStackTrace();
                conn.rollback();
            } catch (SQLException ex) {
                ex.printStackTrace();
            }    
        } finally {
            try {
                conn.setAutoCommit(true);
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return "Failed to cancel reservation " + reservationId + "\n";
    }

    /**
     * Example utility function that uses prepared statements
     */
    private int checkFlightCapacity(int fid) throws SQLException {
        checkFlightCapacityStatement.clearParameters();
        checkFlightCapacityStatement.setInt(1, fid);
        ResultSet results = checkFlightCapacityStatement.executeQuery();
        results.next();
        int capacity = results.getInt("capacity");
        results.close();

        return capacity;
    }

    /**
     * Throw IllegalStateException if transaction not completely complete, rollback.
     * 
     */
    private void checkDanglingTransaction() {
        try {
        try (ResultSet rs = tranCountStatement.executeQuery()) {
            rs.next();
            int count = rs.getInt("tran_count");
            if (count > 0) {
                throw new IllegalStateException(
                "Transaction not fully commit/rollback. Number of transaction in process: " + count);
            }
        } finally {
            conn.setAutoCommit(true);
        }
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    private static boolean isDeadLock(SQLException ex) {
        return ex.getErrorCode() == 1205;
    }

    /**
     * A class to store flight information.
     */
    class Flight {
        public int fid;
        public int dayOfMonth;
        public String carrierId;
        public String flightNum;
        public String originCity;
        public String destCity;
        public int time;
        public int capacity;
        public int price;

        @Override
        public String toString() {
        return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: "
            + flightNum + " Origin: " + originCity + " Dest: " + destCity + " Duration: " + time
            + " Capacity: " + capacity + " Price: " + price + "\n";
        }
    }

    /**
     * A class to store itinerary information.
     */
    class Itinerary {
        public Flight flight1;
        public Flight flight2;

        public boolean directFlight() {
            return flight2 == null;
        }

        public int numFlight() {
            if(directFlight()) {
                return 1;
            }else {
                return 2;
            }
        }

        public int totalTime() {
            if(directFlight()) {
                return flight1.time;
            }else {
                return flight1.time + flight2.time;
            }
        }

        String toString(int index) {
            final StringBuilder output = new StringBuilder();
            output.append("Itinerary ").append(index).append(": ").append(numFlight()).append(" flight(s), ")
                .append(totalTime()).append(" minutes\n");
            output.append(flight1);
            if (!directFlight()) {
                output.append(flight2);
            }
            return output.toString();
        }
        
        // compare flight time first then first flight fid and second flight fid.
        public int compareTo(Itinerary it) {
            int a = this.totalTime() - it.totalTime();
            if(a != 0) { // compare total time first
                return a;
            }
            if (this.directFlight()){ // compare f1.fid then f2.fid
                return this.flight1.fid - it.flight1.fid;
            }else { 
                if(it.directFlight()) {
                    return this.flight1.fid - it.flight1.fid;
                }else {
                    return this.flight2.fid - it.flight2.fid;
                }
            }
        }
    }
}
