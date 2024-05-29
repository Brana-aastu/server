
create database brana;




use brana;

-- Table for resources

CREATE TABLE resources (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255),
    amount INT
);

-- Table for events

CREATE TABLE events (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255),
    place VARCHAR(255),
    time VARCHAR(255),
    description TEXT
);



CREATE TABLE departments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    aid INT
    
);

-- Table for members

CREATE TABLE members (
    id INT PRIMARY KEY AUTO_INCREMENT,
    fname VARCHAR(255),
    mname VARCHAR(255),
    lname VARCHAR(255),
    picture VARCHAR(100),
    did INT,
    FOREIGN KEY (did) REFERENCES departments(id)
);

-- Table for admins

CREATE TABLE admins (
    id INT PRIMARY KEY AUTO_INCREMENT,
    mid INT,
    username VARCHAR(255),
    password VARCHAR(255),
    super TINYINT(1) DEFAULT 0,
    FOREIGN KEY (mid) REFERENCES members(id)
);



-- Table for arts

CREATE TABLE arts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    mid INT,
    title VARCHAR(255),
    description TEXT,
    image VARCHAR(100),
    FOREIGN KEY (mid) REFERENCES members(id)
)


-- Table for requests

CREATE TABLE requests (
    id INT PRIMARY KEY AUTO_INCREMENT,
    did INT,
    message TEXT,
    email VARCHAR(100),
    FOREIGN KEY (did) REFERENCES departments(id)
);



-- Table for session

CREATE TABLE sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    uid INT,
    FOREIGN KEY (uid) REFERENCES admins(id)
);




ALTER TABLE departments
ADD CONSTRAINT FK_aid
FOREIGN KEY (aid) REFERENCES admins(id);
