![Database UML](UML.png)

For this `FlightService.java` program, I created 2 tables `Users` and `Reservations`. 

The `Users` table stored all the users' information include **username** as a unique primary key, encrypted user's password (**hash** and **salt**), and user's **balance**. 

The `Reservations` table stored all the reservations that users have made. In the Reservations table, **rid** as a unique identity primary key which will auto-increment when a new row is inserted, **username** as the foreign key reference to the corresponding user, the **date** of the flight, **flight1fid** as the foreign key reference to the fid in the Flights table, **flight2fid** as the fid for the one-hop flight (null if it is direct flight), **paid** to indicate whether the user pays for the reservation, and **canceled** to indicate the status of the reservation.

Since all the search results will be cleaned when the user performs another search or quit the program. So the search result is temporarily stored in an *`Itinerary Array`* and ready to be stored to the `Reservation` table when the user decides to book the flight.
