-- Database: library_system

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

--
-- Table structure for table `admins`
--

CREATE TABLE `admins` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `avatar` varchar(255) DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `admins`
--

INSERT INTO `admins` (`id`, `name`, `email`, `password`, `avatar`) VALUES
(1, 'Main Admin', 'admin@lms.edu', '$2y$10$C2TzOSeHzwJ/Gk01W6glR.JZybeUYkuq44vl0BQ5fisLlhOEthEim', 'https://picsum.photos/40/40?random=1');
-- Password is '123456' (hashed)

-- --------------------------------------------------------

--
-- Table structure for table `students`
--

CREATE TABLE `students` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `student_id` varchar(50) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `avatar` varchar(255) DEFAULT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `student_id` (`student_id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `students`
--

INSERT INTO `students` (`id`, `student_id`, `name`, `email`, `password`, `avatar`) VALUES
(1, '233016712', 'John Doe', 'johndoe@student.edu', '$2y$10$uTI1ZJL.lJnt6cYc47LjZu0h2cIlAXgaJvdl9ZNSYjBS5W1C9Tb4G', 'https://i.pravatar.cc/150?u=233016712');
-- Password is 'pass123' (hashed)

-- --------------------------------------------------------

--
-- Table structure for table `books`
--

CREATE TABLE `books` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `author` varchar(255) NOT NULL,
  `isbn` varchar(50) NOT NULL,
  `quantity` int(11) NOT NULL DEFAULT 0,
  `available` int(11) NOT NULL DEFAULT 0,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `isbn` (`isbn`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `books`
--

INSERT INTO `books` (`id`, `title`, `author`, `isbn`, `quantity`, `available`) VALUES
(1, 'The Martian', 'Andy Weir', '978-01314290', 10, 8),
(2, 'Deep Learning', 'Ian Goodfellow', '978-01314291', 5, 5),
(3, 'Sapiens', 'Yuval Noah Harari', '978-01314292', 20, 18);

-- --------------------------------------------------------

--
-- Table structure for table `members`
--
-- Note: 'members' in the admin panel seems to refer to registered students or external members.
-- For simplicity, we'll link this to the students table or keep it separate if it's a different entity.
-- Based on the HTML, it has ID, Name, Email, Date. Let's make it a separate table for now as per the HTML logic.

CREATE TABLE `members` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `member_id` varchar(50) NOT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `registered_date` date NOT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `member_id` (`member_id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `members`
--

INSERT INTO `members` (`id`, `member_id`, `name`, `email`, `registered_date`) VALUES
(1, 'S1234', 'Alice Smith', 'alice@student.edu', '2023-01-15'),
(2, 'S5678', 'Bob Johnson', 'bob@student.edu', '2023-03-20');

-- --------------------------------------------------------

--
-- Table structure for table `transactions`
--

CREATE TABLE `transactions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `student_id` varchar(50) NOT NULL, -- Linking to student_id string for flexibility or ID
  `book_id` int(11) NOT NULL,
  `issue_date` date NOT NULL,
  `due_date` date NOT NULL,
  `return_date` date DEFAULT NULL,
  `status` enum('requested','issued','returned','overdue','rejected') NOT NULL DEFAULT 'requested',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `book_id` (`book_id`),
  KEY `student_id` (`student_id`),
  CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`book_id`) REFERENCES `books` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `transactions`
--

INSERT INTO `transactions` (`id`, `student_id`, `book_id`, `issue_date`, `due_date`, `return_date`, `status`) VALUES
(1, '233016712', 1, '2023-11-01', '2023-11-15', NULL, 'issued');

COMMIT;
