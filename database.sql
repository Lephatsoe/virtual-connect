
-- Active: 1741033051742@@127.0.0.1@3306@limkokwing_db-- Active: 1741033051742@@127.0.0.1@3306@limkokwing_db-- Active: 1741033051742@@127.0.0.1@3306@limkokwing_db-- Active: 1740610671055@@127.0.0.1@3306@limkokwing_db-- Active: 1740610671055@@127.0.0.1@3000
show databases;
use limkokwing_db;
show tables;
select * from students;

use limkokwing_db;
CREATE TABLE payments (
    payment_id INT AUTO_INCREMENT PRIMARY KEY,
    student_number INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    method VARCHAR(50) NOT NULL,
    transaction_id VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_number) REFERENCES students(student_number)
);
use limkokwing_db;

