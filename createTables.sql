CREATE TABLE Users(
    username VARCHAR(20) PRIMARY KEY NOT NULL, 
    hash VARBINARY(50) NOT NULL,
    salt VARBINARY(50) NOT NULL,
    balance INT NOT NULL
);

CREATE TABLE Reservations(
    rid INT IDENTITY PRIMARY KEY NOT NULL,
    username VARCHAR (20) REFERENCES Users, 
    date INT NOT NULL,
    flight1id INT NOT NULL REFERENCES Flights(fid),
    flight2id INT,
    paid INT DEFAULT 0,
    cancelled INT DEFAULT 0
);