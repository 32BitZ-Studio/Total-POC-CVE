-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Apr 09, 2023 at 09:10 AM
-- Server version: 10.4.27-MariaDB
-- PHP Version: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `chitor_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `class_subjects`
--

CREATE TABLE `class_subjects` (
  `Id` int(11) NOT NULL,
  `School_Id` int(11) DEFAULT NULL,
  `Class_Id` int(11) NOT NULL,
  `Subject_Id` int(11) NOT NULL,
  `Lock_Status` int(1) NOT NULL DEFAULT 0,
  `Total_Marks` int(3) NOT NULL DEFAULT 40,
  `Status` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `class_subjects`
--

INSERT INTO `class_subjects` (`Id`, `School_Id`, `Class_Id`, `Subject_Id`, `Lock_Status`, `Total_Marks`, `Status`) VALUES
(1, 1, 1, 1, 0, 50, 1),
(2, 1, 2, 1, 0, 100, 1),
(3, 1, 3, 1, 0, 100, 1),
(4, 1, 4, 1, 0, 100, 1),
(5, 1, 5, 1, 0, 100, 1),
(6, 1, 6, 1, 0, 100, 1),
(7, 1, 7, 1, 0, 100, 1),
(9, 1, 1, 2, 0, 100, 1);

-- --------------------------------------------------------

--
-- Table structure for table `employees`
--

CREATE TABLE `employees` (
  `Id` int(2) NOT NULL,
  `Personal_No` int(11) DEFAULT NULL,
  `Name` varchar(30) NOT NULL,
  `Father_Name` varchar(30) DEFAULT NULL,
  `Designation` varchar(20) DEFAULT NULL,
  `Mac_Address` varchar(17) DEFAULT NULL,
  `Mobile_No` varchar(12) DEFAULT NULL,
  `Status` int(2) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `employees`
--

INSERT INTO `employees` (`Id`, `Personal_No`, `Name`, `Father_Name`, `Designation`, `Mac_Address`, `Mobile_No`, `Status`) VALUES
(1, NULL, 'Guest', NULL, NULL, NULL, NULL, 1),
(2, NULL, 'Waqas Ahmad', NULL, NULL, NULL, NULL, 1),
(3, NULL, 'admin', 'admin', 'admin', NULL, NULL, 1);

-- --------------------------------------------------------

--
-- Table structure for table `login`
--

CREATE TABLE `login` (
  `Id` int(11) NOT NULL,
  `Employee_Id` int(11) NOT NULL,
  `User_Name` varchar(30) NOT NULL,
  `Password` varchar(256) NOT NULL,
  `Status` int(11) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `login`
--

INSERT INTO `login` (`Id`, `Employee_Id`, `User_Name`, `Password`, `Status`) VALUES
(1, 1, 'Guest', 'adb831a7fdd83dd1e2a309ce7591dff8', 1),
(2, 2, 'waqaskanju', '119e882fb3cee50d9272ba79822715f5', 1),
(3, 3, 'admin', '21232f297a57a5a743894a0e4a801fc3', 1);

-- --------------------------------------------------------

--
-- Table structure for table `marks`
--

CREATE TABLE `marks` (
  `Serial_No` int(11) NOT NULL,
  `Roll_No` int(11) NOT NULL,
  `English_Marks` int(3) NOT NULL DEFAULT 0,
  `Urdu_Marks` int(3) NOT NULL DEFAULT 0,
  `Maths_Marks` int(3) NOT NULL DEFAULT 0,
  `Science_Marks` int(3) NOT NULL DEFAULT 0,
  `Hpe_Marks` int(3) NOT NULL DEFAULT 0,
  `Nazira_Marks` int(3) NOT NULL DEFAULT 0,
  `History_Marks` int(3) NOT NULL DEFAULT 0,
  `Drawing_Marks` int(3) NOT NULL DEFAULT 0,
  `Islamyat_Marks` int(3) NOT NULL DEFAULT 0,
  `Computer_Marks` int(3) NOT NULL DEFAULT 0,
  `Arabic_Marks` int(3) NOT NULL DEFAULT 0,
  `Mutalia_Marks` int(3) NOT NULL DEFAULT 0,
  `Qirat_Marks` int(3) NOT NULL DEFAULT 0,
  `Pashto_Marks` int(3) NOT NULL DEFAULT 0,
  `Social_Marks` int(3) NOT NULL DEFAULT 0,
  `Biology_Marks` int(3) NOT NULL DEFAULT 0,
  `Chemistry_Marks` int(3) NOT NULL DEFAULT 0,
  `Physics_Marks` int(3) NOT NULL DEFAULT 0,
  `Civics_Marks` int(3) NOT NULL DEFAULT 0,
  `Economics_Marks` int(3) NOT NULL DEFAULT 0,
  `Islamic_Study_Marks` int(3) NOT NULL DEFAULT 0,
  `Islamic_Education_Marks` int(3) NOT NULL DEFAULT 0,
  `Statistics_Marks` int(3) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `position`
--

CREATE TABLE `position` (
  `Serial_No` int(11) NOT NULL,
  `Roll_No` int(11) NOT NULL,
  `Total_Marks` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `position`
--

INSERT INTO `position` (`Serial_No`, `Roll_No`, `Total_Marks`) VALUES
(1460, 2164, 317),
(1461, 2166, 338),
(1462, 2261, 2),
(1463, 2262, 150),
(1464, 2263, 298),
(1465, 2264, 521),
(1466, 2265, 380),
(1467, 2266, 292),
(1468, 2267, 457),
(1469, 2268, 454),
(1470, 2269, 264),
(1471, 21617, 204),
(1472, 21633, 259),
(1473, 21634, 227),
(1474, 21638, 264),
(1475, 21639, 243),
(1476, 21640, 220),
(1477, 22610, 471),
(1478, 22611, 458),
(1479, 22612, 235),
(1480, 22613, 276),
(1481, 22614, 243),
(1482, 22615, 418),
(1483, 22616, 188),
(1484, 22617, 220),
(1485, 22618, 251),
(1486, 22619, 330),
(1487, 22620, 320),
(1488, 22621, 190),
(1489, 22622, 236),
(1490, 22623, 157),
(1491, 22624, 201),
(1492, 22625, 206),
(1493, 22626, 218),
(1494, 22627, 165),
(1495, 22628, 131),
(1496, 22629, 176),
(1497, 22630, 221),
(1498, 22631, 192),
(1499, 22632, 227),
(1500, 22633, 261),
(1501, 22634, 271),
(1502, 22635, 242),
(1503, 22636, 263),
(1504, 22637, 216),
(1505, 22638, 353),
(1506, 22639, 272),
(1507, 22640, 238),
(1508, 22641, 354),
(1509, 22642, 299),
(1510, 22643, -8),
(1511, 22645, 205);

-- --------------------------------------------------------

--
-- Table structure for table `schools`
--

CREATE TABLE `schools` (
  `Id` int(11) NOT NULL,
  `Name` varchar(30) NOT NULL,
  `Status` int(2) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `schools`
--

INSERT INTO `schools` (`Id`, `Name`, `Status`) VALUES
(1, 'GHSS Chitor', 1),
(2, 'GMS Marghazar', 1),
(3, 'GMS Spal Bandai', 1),
(4, 'GPS Kokrai', 1),
(5, 'GPS Chitor', 1),
(6, 'GCPS Jabba', 1),
(7, 'Iqra', 1),
(8, 'Anfal', 1);

-- --------------------------------------------------------

--
-- Table structure for table `school_classes`
--

CREATE TABLE `school_classes` (
  `Id` int(11) NOT NULL,
  `Name` varchar(20) NOT NULL,
  `School_Id` int(2) NOT NULL,
  `Pass_Percentage` float NOT NULL DEFAULT 0,
  `Status` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `school_classes`
--

INSERT INTO `school_classes` (`Id`, `Name`, `School_Id`, `Pass_Percentage`, `Status`) VALUES
(1, '6th', 1, 20, 1),
(2, '7th', 1, 19.4, 1),
(3, '8th', 1, 24, 1),
(4, '9th A', 1, 33, 1),
(5, '9th B', 1, 33, 1),
(6, '10th A', 1, 33, 1),
(7, '10th B', 1, 33, 1),
(8, '5th', 5, 19.4, 1),
(14, '8th', 2, 24, 1),
(16, '5th', 6, 19.4, 1),
(17, '5th', 4, 19.4, 1),
(18, '8th', 3, 24, 1),
(22, '8th', 6, 33.3, 1),
(23, '5th', 1, 19.4, 1),
(25, '4th', 1, 19.4, 1);

-- --------------------------------------------------------

--
-- Table structure for table `setting`
--

CREATE TABLE `setting` (
  `User_Id` int(11) NOT NULL,
  `Selected_School_Id` int(11) NOT NULL DEFAULT 1,
  `Selected_Class_Id` int(11) NOT NULL DEFAULT 1,
  `Student_Changes` int(1) NOT NULL DEFAULT 0,
  `Batch_Marks_Changes` int(1) NOT NULL DEFAULT 0,
  `Single_Marks_Changes` int(1) NOT NULL DEFAULT 0,
  `Subject_Changes` int(1) NOT NULL DEFAULT 0,
  `School_Changes` int(1) NOT NULL DEFAULT 0,
  `Marks_Lock_Changes` int(1) NOT NULL DEFAULT 0,
  `Permission_Changes` int(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `setting`
--

INSERT INTO `setting` (`User_Id`, `Selected_School_Id`, `Selected_Class_Id`, `Student_Changes`, `Batch_Marks_Changes`, `Single_Marks_Changes`, `Subject_Changes`, `School_Changes`, `Marks_Lock_Changes`, `Permission_Changes`) VALUES
(1, 1, 1, 0, 0, 0, 0, 9, 0, 0),
(2, 1, 1, 1, 1, 1, 1, 1, 1, 1),
(3, 1, 1, 1, 11, 1, 1, 1, 1, 1);

-- --------------------------------------------------------

--
-- Table structure for table `students_info`
--

CREATE TABLE `students_info` (
  `Roll_No` int(11) NOT NULL,
  `Name` varchar(30) NOT NULL,
  `FName` varchar(30) NOT NULL,
  `Gender` enum('Male','Female') NOT NULL DEFAULT 'Male',
  `Dob` date DEFAULT NULL,
  `Mobile_No` varchar(12) NOT NULL DEFAULT '03',
  `Admission_Date` date DEFAULT NULL,
  `Admission_No` int(6) DEFAULT NULL,
  `Father_Cnic` varchar(15) DEFAULT NULL,
  `Student_Form_B` varchar(15) DEFAULT NULL,
  `School` varchar(30) NOT NULL DEFAULT 'GHSS CHITOR',
  `Class` enum('5th','6th A','6th B','7th','8th A','8th B','8th','10th A','10th B','9th A','9th B','6th','7th A','7th B','4th','11th') NOT NULL,
  `Class_Position` varchar(10) DEFAULT NULL,
  `Status` int(11) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `students_info`
--

INSERT INTO `students_info` (`Roll_No`, `Name`, `FName`, `Gender`, `Dob`, `Mobile_No`, `Admission_Date`, `Admission_No`, `Father_Cnic`, `Student_Form_B`, `School`, `Class`, `Class_Position`, `Status`) VALUES
(1, 'Abdul Salam', 'Hamidullah', 'Male', '1900-01-01', '03', '2023-03-11', 1, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(2, 'Zakirullah', 'Wazir', 'Male', '1900-01-01', '03', '2023-03-11', 2, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(3, 'Zeeshan Khan', 'Hamza Khan', 'Male', '1900-01-01', '03', '2023-03-11', 3, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(4, 'Muhammad Awais', 'Suleman', 'Male', '1900-01-01', '03', '2023-03-11', 4, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(5, 'Aftab Ali', 'Izat Muhammad', 'Male', '1900-01-01', '03', '2023-03-11', 5, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(6, 'Abbas Khan', 'Nazir Ahmad', 'Male', '1900-01-01', '03', '2023-03-11', 6, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(7, 'Muhammad Luqman', 'Bakht Baidar', 'Male', '1900-01-01', '03', '2023-03-11', 7, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(8, 'Mobin Khan', 'Muhammad Khan', 'Male', '1900-01-01', '03', '2023-03-11', 8, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(9, 'Sana Younis', 'Muhammad Younis', 'Male', '1900-01-01', '03', '2023-03-11', 9, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(10, 'Wareesha Bibi', 'Sabz Ali Khan', 'Male', '1900-01-01', '03', '2023-03-11', 10, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(11, 'Bibi Sawera Ibrahim', 'Ibrahim', 'Male', '1900-01-01', '03', '2023-03-11', 11, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(12, 'Muneeba Bibi', 'Ghani Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 12, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(13, 'Sana Begum', 'Haji Nawab', 'Male', '1900-01-01', '03', '2023-03-11', 13, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(14, 'Madeeha Bibi', 'Shah Wazir Khan', 'Male', '1900-01-01', '03', '2023-03-11', 14, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(15, 'Bibi Jaweria Ibrahim', 'Ibrahim', 'Male', '1900-01-01', '03', '2023-03-11', 15, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(16, 'Emad Khan', 'Rahim Shah', 'Male', '1900-01-01', '03', '2023-03-11', 16, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(17, 'Rashid Iqbal', 'Iqbal Rawan', 'Male', '1900-01-01', '03', '2023-03-11', 17, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(18, 'Fazal Wahab', 'Akbar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 18, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(19, 'Muhammad Asif', 'Fazal Ali', 'Male', '1900-01-01', '03', '2023-03-11', 19, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(20, 'Abdul Aziz', 'Afzal', 'Male', '1900-01-01', '03', '2023-03-11', 20, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(21, 'Asif Khan', 'Fazal Hadi', 'Male', '1900-01-01', '03', '2023-03-11', 21, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(22, 'Asif Khan', 'Sher Ali Khan', 'Male', '1900-01-01', '03', '2023-03-11', 22, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(23, 'Said Nawab', 'Khewa Gul', 'Male', '1900-01-01', '03', '2023-03-11', 0, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(24, 'Asif Khan', 'Shah Wazir Khan', 'Male', '1900-01-01', '03', '2023-03-11', 24, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(25, 'Abdullah', 'Muhammad Sher', 'Male', '1900-01-01', '03', '2023-03-11', 25, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(26, 'Rahman Ali', 'Karim Khan', 'Male', '1900-01-01', '03', '2023-03-11', 26, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(27, 'Abdullah', 'Zafar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 27, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(28, 'Muhammad Kashif', 'Ashraf Ali', 'Male', '1900-01-01', '03', '2023-03-11', 28, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(29, 'Junaid Khan', 'Zafar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 29, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(30, 'Muhammad Zubair', 'Anwar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 30, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(31, 'Sohail Khan', 'Bakht Sherawan', 'Male', '1900-01-01', '03', '2023-03-11', 31, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(32, 'Ikramullah', 'Umar Gul', 'Male', '1900-01-01', '03', '2023-03-11', 32, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(33, 'Moeez Haidar ', 'Rahman Haidar', 'Male', '1900-01-01', '03', '2023-03-11', 33, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(34, 'Muhammad Shawal', 'Muhammad Naeem', 'Male', '1900-01-01', '03', '2023-03-11', 34, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(35, 'Muhammad Asif', 'Habib Ur Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 35, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(36, 'Salahuddin', 'Muhammad Naseeruddin', 'Male', '1900-01-01', '03', '2023-03-11', 36, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(37, 'Rahmat Khan', 'Gul Zarin', 'Male', '1900-01-01', '03', '2023-03-11', 37, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(38, 'Waqar Khan', 'Amin Ur Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 38, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(39, 'Aman Ali', 'Iqrar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 39, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(40, 'Asad Ali', 'Haidar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 40, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(41, 'Muhammad Shoaib', 'Zafar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 41, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(42, 'Niaz Alam', 'Khursed Alam', 'Male', '1900-01-01', '03', '2023-03-11', 42, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(43, 'Tauseefullah', 'Shah Wazir Khan', 'Male', '1900-01-01', '03', '2023-03-11', 43, '15602-', '15602-', 'GPS Kokrai', '5th', '', 1),
(51, 'Hazratullah', 'Umar Zahir', 'Male', '1900-01-01', '03', '2023-03-11', 51, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(52, 'Noorul Amin', 'Ahmad Ali', 'Male', '1900-01-01', '03', '2023-03-11', 52, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(53, 'Abubakr', 'Sher Alam', 'Male', '1900-01-01', '03', '2023-03-11', 53, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(54, 'Muhammad Salman', 'Jehan Zada', 'Male', '1900-01-01', '03', '2023-03-11', 54, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(55, 'Fawad Ali', 'Mian Said Ghani', 'Male', '1900-01-01', '03', '2023-03-11', 55, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(56, 'Mehboob Ali', 'Usman Ali', 'Male', '1900-01-01', '03', '2023-03-11', 56, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(57, 'Rafiullah', 'Mian Jan Ghani', 'Male', '1900-01-01', '03', '2023-03-11', 57, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(58, 'Jalwa Bibi', 'Fazal Akbar', 'Male', '1900-01-01', '03', '2023-03-11', 58, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(59, 'Muhammad Suliman', 'Shehzada', 'Male', '1900-01-01', '03', '2023-03-11', 59, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(60, 'Iqra Bibi', 'Rahmat Ali', 'Male', '1900-01-01', '03', '2023-03-11', 60, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(61, 'Ziaullah', 'Umar Zaman', 'Male', '1900-01-01', '03', '2023-03-11', 61, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(62, 'Majidullah', 'Azim Khan', 'Male', '1900-01-01', '03', '2023-03-11', 62, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(63, 'Majida Bibi', 'Muhammad Ishaq', 'Male', '1900-01-01', '03', '2023-03-11', 63, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(64, 'Abdur Rahman', 'Shtha Mand', 'Male', '1900-01-01', '03', '2023-03-11', 64, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(65, 'Husna Begum', 'Amir Zaman', 'Male', '1900-01-01', '03', '2023-03-11', 65, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(66, 'Maryana', 'Rahman Gul', 'Male', '1900-01-01', '03', '2023-03-11', 66, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(67, 'Sanullah', 'Abdul Zahir', 'Male', '1900-01-01', '03', '2023-03-11', 67, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(68, 'Bushra Begum', 'Nazir Gul', 'Male', '1900-01-01', '03', '2023-03-11', 68, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(69, 'Muhammad Ismail', 'Fazal Subhan', 'Male', '1900-01-01', '03', '2023-03-11', 69, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(70, 'Muhammad Bilal', 'Nasib Zada', 'Male', '1900-01-01', '03', '2023-03-11', 70, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(71, 'Rehana Begum', 'Inayat Ur Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 71, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(72, 'Abdullah', 'Umar Zarin', 'Male', '1900-01-01', '03', '2023-03-11', 72, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(73, 'Bakht Amin', 'Ahmad Ali', 'Male', '1900-01-01', '03', '2023-03-11', 73, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(74, 'Ikramullah', 'Shah Bahadar', 'Male', '1900-01-01', '03', '2023-03-11', 74, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(75, 'Rahmat Gul', 'Nasib Gul', 'Male', '1900-01-01', '03', '2023-03-11', 75, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(76, 'Arosa Ismail', 'Ismail Shah', 'Male', '1900-01-01', '03', '2023-03-11', 76, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(77, 'Maaz Ali Shah', 'Zarawar Shah', 'Male', '1900-01-01', '03', '2023-03-11', 77, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(78, 'Hasan Shah', 'Ismail Shah', 'Male', '1900-01-01', '03', '2023-03-11', 78, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(79, 'Fazal Nabi', 'Fazal Wahid', 'Male', '1900-01-01', '03', '2023-03-11', 79, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(80, 'Noor Muhammad', 'Said Muhammad', 'Male', '1900-01-01', '03', '2023-03-11', 80, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(81, 'Muhammad Anas Khan', 'Fazal Subhan', 'Male', '1900-01-01', '03', '2023-03-11', 81, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(82, 'Muhammad Kmran', 'Muhammad Kamal', 'Male', '1900-01-01', '03', '2023-03-11', 82, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(83, 'Mazhar Ali', 'Asghar', 'Male', '1900-01-01', '03', '2023-03-11', 83, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(84, 'Kashif Rashid', 'Rashid Iqbal', 'Male', '1900-01-01', '03', '2023-03-11', 84, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(85, 'Muhammad Hasan', 'Fazal Zahid', 'Male', '1900-01-01', '03', '2023-03-11', 85, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(86, 'Ahmad Hussain', 'Muhammad Zahir Shah', 'Male', '1900-01-01', '03', '2023-03-11', 86, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(87, 'Rafiullah', 'Anwar Ali', 'Male', '1900-01-01', '03', '2023-03-11', 87, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(88, 'Suliman Khan', 'Fazal Zahid', 'Male', '1900-01-01', '03', '2023-03-11', 88, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(89, 'Mutafa', 'Muhammad Jan', 'Male', '1900-01-01', '03', '2023-03-11', 89, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(90, 'Shafiq Rahim', 'Fazal Rahim', 'Male', '1900-01-01', '03', '2023-03-11', 90, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(91, 'Muhammad Umar', 'Sayyed Yousaf Shah', 'Male', '1900-01-01', '03', '2023-03-11', 91, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(92, 'Modasir Shah', 'Shah Bahadar', 'Male', '1900-01-01', '03', '2023-03-11', 92, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(93, 'Muhammad Ibrar', 'Rozi Gul', 'Male', '1900-01-01', '03', '2023-03-11', 93, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(94, 'Alam Zeb', 'Jehan Zeb', 'Male', '1900-01-01', '03', '2023-03-11', 94, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(95, 'Abdul Wahab Khan', 'Fazal Wahid', 'Male', '1900-01-01', '03', '2023-03-11', 95, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(96, 'Muhammad Talha', 'Umar Wahid', 'Male', '1900-01-01', '03', '2023-03-11', 96, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(97, 'Sanan Ali', 'Parvish', 'Male', '1900-01-01', '03', '2023-03-11', 97, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(98, 'Muhammad Ishaq', 'Umar Badshah', 'Male', '1900-01-01', '03', '2023-03-11', 98, '15602-', '15602-', 'GPS Chitor', '5th', '', 1),
(101, 'Habibullah', 'Wahid Zada', 'Male', '1900-01-01', '03', '2023-03-11', 101, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(102, 'Abdullah', 'Bacha Khan', 'Male', '1900-01-01', '03', '2023-03-11', 102, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(103, 'Ubaidullah', 'Afzal Khan', 'Male', '1900-01-01', '03', '2023-03-11', 103, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(104, 'Idress Khan', 'Khaista Ali', 'Male', '1900-01-01', '03', '2023-03-11', 105, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(105, 'Khanullah', 'Bakht Sherrawan', 'Male', '1900-01-01', '03', '2023-03-11', 106, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(106, 'Aizazullah', 'Aziz Ur Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 107, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(107, 'Naveedullah', 'Rahim Zada', 'Male', '1900-01-01', '03', '2023-03-11', 108, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(108, 'Izharullah', 'Habib Un Nabi', 'Male', '1900-01-01', '03', '2023-03-11', 109, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(109, 'Saifullah', 'Azim Khan', 'Male', '1900-01-01', '03', '2023-03-11', 110, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(110, 'Abubakar Khan', 'yousaf Khan', 'Male', '1900-01-01', '03', '2023-03-11', 111, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(111, 'Fazlullah', 'Khurshaid Ali', 'Male', '1900-01-01', '03', '2023-03-11', 112, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(112, 'Hazrat Ali', 'Bakht Sher', 'Male', '1900-01-01', '03', '2023-03-11', 113, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(113, 'Uzairullah', 'Ismail', 'Male', '1900-01-01', '03', '2023-03-11', 114, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(114, 'Sajjad Ali', 'Nasir Ali', 'Male', '1900-01-01', '03', '2023-03-11', 115, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(115, 'Saidullah', 'Taza GUl', 'Male', '1900-01-01', '03', '2023-03-11', 116, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(116, 'Muhammad Maaz Khan', 'Amir Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 117, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(117, 'Muhammad Abdullah', 'Iqbal Muhammad', 'Male', '1900-01-01', '03', '2023-03-11', 118, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(118, 'Fawad Ali', 'Mumtaz Khan', 'Male', '1900-01-01', '03', '2023-03-11', 119, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(119, 'Hanif Ahmad', 'Nisar Ahmad', 'Male', '1900-01-01', '03', '2023-03-11', 120, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(120, 'Amanullah', 'Umar Qayum', 'Male', '1900-01-01', '03', '2023-03-11', 121, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(121, 'Nazamullah', 'Abdul Hakim Khan', 'Male', '1900-01-01', '03', '2023-03-11', 122, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(122, 'Matiullah', 'Abdul Razaq', 'Male', '1900-01-01', '03', '2023-03-11', 123, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(123, 'Sohail Ahmad', 'Usman Ali', 'Male', '1900-01-01', '03', '2023-03-11', 124, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(124, 'Shakirullah', 'Ishaq', 'Male', '1900-01-01', '03', '2023-03-11', 125, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(125, 'Salman Khan', 'Khairate', 'Male', '1900-01-01', '03', '2023-03-11', 126, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(126, 'Shahab Khan', 'Sarbali', 'Male', '1900-01-01', '03', '2023-03-11', 127, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(127, 'Abidullah', 'Mujahid', 'Male', '1900-01-01', '03', '2023-03-11', 128, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(128, 'Zakirullah', 'Bakhti Alam', 'Male', '1900-01-01', '03', '2023-03-11', 129, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(129, 'Muhammad Abbas', 'Umar Ghani', 'Male', '1900-01-01', '03', '2023-03-11', 130, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(130, 'Abdul Basit', 'Fazal Qayum', 'Male', '1900-01-01', '03', '2023-03-11', 131, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(131, 'Abbas Khan', 'Bakht Zada', 'Male', '1900-01-01', '03', '2023-03-11', 132, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(132, 'Kashif Ali', 'Muhammad Nabi', 'Male', '1900-01-01', '03', '2023-03-11', 133, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(133, 'Arshad Ali', 'Qaisar Khan', 'Male', '1900-01-01', '03', '2023-03-11', 134, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(134, 'Zahid Ahmad', 'Dawa Khan', 'Male', '1900-01-01', '03', '2023-03-11', 135, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(135, 'Suhail Khan', 'Fazal Qayum', 'Male', '1900-01-01', '03', '2023-03-11', 136, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(136, 'Nizamullah', 'Muhammd Ishaq', 'Male', '1900-01-01', '03', '2023-03-11', 137, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(137, 'Numan Khan', 'Lal Zada', 'Male', '1900-01-01', '03', '2023-03-11', 138, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(138, 'Ajmir Shah', 'Aslam Pervaiz', 'Male', '1900-01-01', '03', '2023-03-11', 139, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(139, 'Afsar Ali', 'Pervaiz', 'Male', '1900-01-01', '03', '2023-03-11', 140, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(140, 'Zahid Husain', 'Umar Khan', 'Male', '1900-01-01', '03', '2023-03-11', 141, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(141, 'Mohiburahman', 'Abdur Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 142, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(142, 'Adnan Bacha', 'Fazal Khan', 'Male', '1900-01-01', '03', '2023-03-11', 143, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(143, 'Azizullah', 'Abdul Wahid', 'Male', '1900-01-01', '03', '2023-03-11', 144, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(144, 'Muhammad Idress', 'Muhammad Zaman', 'Male', '1900-01-01', '03', '2023-03-11', 145, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(145, 'Ikramullah', 'Umar Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 146, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(146, 'Ihsanullah', 'Ibrahim', 'Male', '1900-01-01', '03', '2023-03-11', 147, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(147, 'Abdullah Khan', 'Farman Ullah', 'Male', '1900-01-01', '03', '2023-03-11', 148, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(148, 'Uzman Ali', 'Dost Muhammad Khan', 'Male', '1900-01-01', '03', '2023-03-11', 149, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(149, 'Azizurrahman', 'Gul Rahman', 'Male', '1900-01-01', '03', '2023-03-11', 150, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(150, 'Hazratullah', 'Alam Khan', 'Male', '1900-01-01', '03', '2023-03-11', 151, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(151, 'Ubaidullah', 'Muhammad Noor', 'Male', '1900-01-01', '03', '2023-03-11', 152, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(152, 'Muhammad Sadam', 'Barkat Ali', 'Male', '1900-01-01', '03', '2023-03-11', 153, '15602-', '15602-', 'GMS Marghazar', '8th', '', 1),
(201, 'Muhammad Khan', 'Sabir Gul', 'Male', '1900-01-01', '03', '2023-03-11', 201, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(202, 'Akbar Said Khan', 'Said Akbar', 'Male', '1900-01-01', '03', '2023-03-11', 202, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(203, 'Fazal Mahboob', 'Gul Rehman', 'Male', '1900-01-01', '03', '2023-03-11', 203, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(204, 'Sultani Room', 'Amani Room', 'Male', '1900-01-01', '03', '2023-03-11', 204, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(205, 'Hazrat Bilal', 'Sabir Gul', 'Male', '1900-01-01', '03', '2023-03-11', 205, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(206, 'Sajjad Khan', 'Gul Bashar', 'Male', '1900-01-01', '03', '2023-03-11', 206, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(207, 'Asmat Khan', 'Rehmat Khan', 'Male', '1900-01-01', '03', '2023-03-11', 207, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(208, 'Muhammad Yasin', 'Yaad Muhammad Khan', 'Male', '1900-01-01', '03', '2023-03-11', 208, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(209, 'Jan Alam', 'Jan Ali', 'Male', '1900-01-01', '03', '2023-03-11', 209, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(210, 'Amjad Ali', 'Amir Zaman', 'Male', '1900-01-01', '03', '2023-03-11', 210, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(211, 'Imran Khan', 'Dost Muhammad Khan', 'Male', '1900-01-01', '03', '2023-03-11', 211, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(212, 'Iqbal Hussain', 'Rozi Khan', 'Male', '1900-01-01', '03', '2023-03-11', 212, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(213, 'Ikram Hussain', 'Momin Khan', 'Male', '1900-01-01', '03', '2023-03-11', 213, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(214, 'Haidar Alam', 'Nasib Khan', 'Male', '1900-01-01', '03', '2023-03-11', 214, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(215, 'Muhammad Sadiq', 'Sher Baz khan', 'Male', '1900-01-01', '03', '2023-03-11', 215, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(216, 'Muhammad Hassan', 'Ismail', 'Male', '1900-01-01', '03', '2023-03-11', 216, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(217, 'Luqman Alam', 'Alam Sher', 'Male', '1900-01-01', '03', '2023-03-11', 217, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(218, 'Muhammad Ayyaz', 'Sher Zaman', 'Male', '1900-01-01', '03', '2023-03-13', 218, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(219, 'Akram Said', 'Wazir Zada', 'Male', '1900-01-01', '03', '2023-03-13', 219, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(220, 'Azam Khan', 'Gul Khan', 'Male', '1900-01-01', '03', '2023-03-13', 220, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(221, 'Niaz Ali', 'Barooz Khan', 'Male', '1900-01-01', '03', '2023-03-13', 221, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(222, 'Kamran Akmal', 'Abdul Kabeer', 'Male', '1900-01-01', '03', '2023-03-13', 222, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(223, 'Saidullah', 'Bakht Sherwan', 'Male', '1900-01-01', '03', '2023-03-13', 223, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(224, 'Kausar Ali', 'Baghi Gul', 'Male', '1900-01-01', '03', '2023-03-13', 224, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(225, 'Fazal Ghani', 'Ismail', 'Male', '1900-01-01', '03', '2023-03-13', 225, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(226, 'Zubairullah', 'Umar Hayyat', 'Male', '1900-01-01', '03', '2023-03-13', 226, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(227, 'Irfan Ali', 'Yaqoob Khan', 'Male', '1900-01-01', '03', '2023-03-13', 227, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(228, 'Muhammad Yasin', 'Sarfaraz Khan', 'Male', '1900-01-01', '03', '2023-03-13', 228, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(229, 'Ijaz Khan', 'Amin Khan', 'Male', '1900-01-01', '03', '2023-03-13', 229, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(230, 'Fida Hussain', 'Iqbal Hussain', 'Male', '1900-01-01', '03', '2023-03-13', 230, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(231, 'Saifullah Khan', 'Muhammad Akbar', 'Male', '1900-01-01', '03', '2023-03-13', 231, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(232, 'Rafiullah', 'Yahya Khan', 'Male', '1900-01-01', '03', '2023-03-13', 232, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(233, 'Shah Faisal', 'Amir Hamza', 'Male', '1900-01-01', '03', '2023-03-13', 233, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(234, 'Faridoon Khan', 'Mahabat Khan', 'Male', '1900-01-01', '03', '2023-03-13', 234, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(235, 'Ali Rehman', 'Abdur Rehman', 'Male', '1900-01-01', '03', '2023-03-13', 235, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(236, 'Rahimullah', 'Bakht Rawan', 'Male', '1900-01-01', '03', '2023-03-13', 236, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(237, 'Bilal Khan', 'Amir Dost Khan', 'Male', '1900-01-01', '03', '2023-03-13', 237, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(238, 'Zahir Rehman', 'Noor Rehman', 'Male', '1900-01-01', '03', '2023-03-13', 238, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(239, 'Shahzad Khan', 'Umar Wahid', 'Male', '1900-01-01', '03', '2023-03-13', 239, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(240, 'Hassan Khan', 'Rob Ali Khan', 'Male', '1900-01-01', '03', '2023-03-13', 240, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(241, 'Rahimullah', 'Rahim Khan', 'Male', '1900-01-01', '03', '2023-03-13', 241, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(242, 'Shaukat Ali', 'Luqman Ali', 'Male', '1900-01-01', '03', '2023-03-13', 242, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(243, 'Muhammad Usama', 'Bahadar Khan', 'Male', '1900-01-01', '03', '2023-03-13', 243, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(244, 'Hassan Khan', 'Bakht Alam', 'Male', '1900-01-01', '03', '2023-03-13', 244, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(245, 'Bilal Khan', 'Mian Said Alam', 'Male', '1900-01-01', '03', '2023-03-13', 245, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(246, 'Jamilullah', 'Sher Zada', 'Male', '1900-01-01', '03', '2023-03-13', 246, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(247, 'Najibullah', 'Iqbal Zaman', 'Male', '1900-01-01', '03', '2023-03-13', 247, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(248, 'Shah Fahad', 'Wahid Zaman', 'Male', '1900-01-01', '03', '2023-03-13', 248, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(249, 'Hasnain Khan', 'Liaqat Ali', 'Male', '1900-01-01', '03', '2023-03-13', 249, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(250, 'Hassan Khan', 'Fazal Wahid', 'Male', '1900-01-01', '03', '2023-03-13', 250, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(251, 'Muhammad Musa', 'Hayya Khan', 'Male', '1900-01-01', '03', '2023-03-13', 251, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(252, 'Gohar Ali', 'Sad Bar Ali', 'Male', '1900-01-01', '03', '2023-03-13', 252, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(253, 'Muhammad Shahab', 'Umar Gul', 'Male', '1900-01-01', '03', '2023-03-13', 253, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(254, 'Muhammad Fawad', 'Khan Shereen', 'Male', '1900-01-01', '03', '2023-03-13', 254, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(255, 'Muhammad Irfan', 'Khan Shereen', 'Male', '1900-01-01', '03', '2023-03-13', 255, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(256, 'Fazal Khan', 'Afzal Khan', 'Male', '1900-01-01', '03', '2023-03-13', 256, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(257, 'Zohaibullah', 'Ihsanullah', 'Male', '1900-01-01', '03', '2023-03-13', 257, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(258, 'Said Alam Khan', 'Sarfaraz Khan', 'Male', '1900-01-01', '03', '2023-03-13', 258, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(259, 'Abdul Aziz', 'Akbar Khan', 'Male', '1900-01-01', '03', '2023-03-13', 259, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(260, 'Hamidullah', 'Shah Fahad', 'Male', '1900-01-01', '03', '2023-03-13', 260, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(261, 'Muhammad Hamza', 'Noorul Bashar', 'Male', '1900-01-01', '03', '2023-03-13', 261, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(262, 'Muhammad Ismail', 'Shah Room Khan', 'Male', '1900-01-01', '03', '2023-03-13', 262, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(263, 'Umar Hayyat', 'Pasham Gul', 'Male', '1900-01-01', '03', '2023-03-13', 263, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(264, 'Daoud Khan', 'Zaiwar Khan', 'Male', '1900-01-01', '03', '2023-03-13', 264, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(265, 'Usman Ali', 'Amir Zaman', 'Male', '1900-01-01', '03', '2023-03-13', 265, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(266, 'Muhammad Nouman', 'Wazir', 'Male', '1900-01-01', '03', '2023-03-13', 266, '15602-', '15602-', 'GMS Spal Bandai', '8th', '', 1),
(301, 'Fatima Bibi', 'Amal Khan', 'Male', '1900-01-01', '03', '2023-03-13', 301, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(302, 'Omama Bibi', 'Shah Bali Khan', 'Male', '1900-01-01', '03', '2023-03-13', 302, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(303, 'Sabila Umar', 'Umar', 'Male', '1900-01-01', '03', '2023-03-13', 303, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(304, 'Mastoriya Bibi', 'Saif Ur Rahman', 'Male', '1900-01-01', '03', '2023-03-13', 304, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(305, 'Fazal Sadiq', 'Fazal Gul', 'Male', '1900-01-01', '03', '2023-03-13', 305, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(306, 'Umar Sadiq', 'Nazeer Gul', 'Male', '1900-01-01', '03', '2023-03-13', 306, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(307, 'Nadeem Khan', 'Janfar Ali', 'Male', '1900-01-01', '03', '2023-03-13', 307, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(308, 'Hazrat Ali', 'Gulfar Ali', 'Male', '1900-01-01', '03', '2023-03-13', 308, '15602-', '15602-', 'GCPS Jabba', '5th', '', 1),
(1008, 'Waqas', 'Ahmad', 'Male', '1900-01-01', '03', '2023-04-06', 10078, '15602-', '15602-', 'GHSS Chitor', '7th', '', 1),
(2161, 'Shahid Khan', 'Said Jalil', 'Male', '2010-01-10', '0344-3085547', '2021-07-01', 3616, '15602-0246072-7', '', 'GHSS Chitor', '7th', '', 1),
(2162, 'Ibrar Khan', 'Amin Ur Rahman', 'Male', '2010-05-15', '03', '2021-07-12', 3617, '', '', 'GHSS Chitor', '7th', '', 1),
(2163, 'Muhammad Sudais', 'Suliman', 'Male', '2009-09-18', '03', '2021-07-12', 3618, '', '', 'GHSS Chitor', '7th', '', 1),
(2164, 'Kashif Khan', 'Painda Mand', 'Male', '2011-12-16', '0324-9860945', '2021-07-12', 3619, '15602-7884572-5', '15602', 'GHSS Chitor', '7th', '', 1),
(2165, 'Mujeeb ur Rahman', 'Gauhar Ali', 'Male', '2009-06-12', '0345-1951101', '2021-07-12', 3621, '15602-0970446-3', '', 'GHSS Chitor', '7th', '', 1),
(2166, 'Muhammad Amin', 'Haji Nawab', 'Male', '2010-03-10', '0348-1895804', '2021-07-12', 3622, '15602-2712381-5', '', 'GHSS Chitor', '7th', '', 1),
(2167, 'Adil Khan', 'Fazal Hadi', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(2168, 'Umar Rahman', 'Jehanzeb', 'Male', '2008-06-03', '0347-1368173', '2021-07-12', 3624, '15602-0250842-5', '', 'GHSS Chitor', '7th', '', 1),
(2169, 'Muhammad Taib', 'Sher Ali Khan', 'Male', '2010-03-25', '0344-9065459', '2021-07-12', 3625, '15602-6606220-3', '', 'GHSS Chitor', '7th', '', 1),
(2181, 'Shah Faisal', 'Ibrahim', 'Male', '2007-05-22', '0307-8523101', '1900-01-01', 4180, '15602-5264648-5', '', 'GHSS Chitor', '9th A', '', 1),
(2182, 'Muhammad Imran', 'Khan Zada', 'Male', '1900-01-01', '0343-9406706', '1900-01-01', 4181, '', '', 'GHSS Chitor', '9th A', '', 0),
(2183, 'Wajid Ali', 'Hakeem Zada', 'Male', '2006-04-25', '0341-9073164', '1900-01-01', 4182, '15607-0577920-1', '', 'GHSS Chitor', '9th A', '', 1),
(2184, 'Samiullah', 'Said Muhammad', 'Male', '2007-04-17', '0341-9030360', '1900-01-01', 4183, '15602-0716932-1', '', 'GHSS Chitor', '9th A', '', 1),
(2185, 'Abu Bakar', 'Irfan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '9th A', '', 0),
(2186, 'Ali Said', 'Jehan Zeb', 'Male', NULL, '0349-3551351', NULL, NULL, NULL, NULL, 'GHSS Chitor', '9th A', '', 0),
(2187, 'Inamullah Khan', 'Muhammad Jan', 'Male', '1900-01-01', '0347-4766609', '1900-01-01', 852, '', '', 'GHSS Chitor', '8th', '', 1),
(2188, 'Muhammad Shoaib', 'Qadar Gul', 'Male', '2007-03-02', '0345-9311847', '1900-01-01', 4184, '15602-7150208-7', '', 'GHSS Chitor', '9th A', '', 1),
(2189, 'Ata Ur Rahman', 'Bakht Rahman', 'Male', '2004-12-22', '0344-9636710', '1900-01-01', 4185, '15602-0458901-1', '', 'GHSS Chitor', '9th A', '', 1),
(2261, 'Ihsan Ali', 'Muhammad Ishaq', 'Male', '2007-02-02', '0342-9638859', '2022-08-16', 3658, '15602-0244886-3', '03', 'GHSS Chitor', '8th', '', 1),
(2262, 'Rahman Ali', 'Liaqat Ali', 'Male', '2009-01-01', '0345-9013977', '2022-08-16', 3669, '15602-0250875-1', '03', 'GHSS Chitor', '7th', '', 1),
(2263, 'Ikram Ullah', 'Imran Khan', 'Male', '2011-06-16', '0341-5475886', '2022-08-16', 3678, '15602-7834710-5', '03', 'GHSS Chitor', '6th', '', 1),
(2264, 'Jawad Khan', 'Umar Rahim', 'Male', '2011-03-20', '0340-9241403', '2022-08-16', 3679, '15602-8763638-1', '03', 'GHSS Chitor', '6th', '', 1),
(2265, 'Minhaz Ali', 'Bakhti Gul', 'Male', '2011-07-21', '0342-9901699', '2022-08-16', 3680, '15602-0458302-1', '03', 'GHSS Chitor', '6th', '', 1),
(2266, 'Muhammad Yasir', 'Sajid Ali', 'Male', '2011-08-30', '0348-4406611', '2022-08-16', 3681, '15602-3010992-1', '03', 'GHSS Chitor', '6th', '', 1),
(2267, 'Zohaib Khan', 'Inayat Ur Rahman', 'Male', '2011-10-30', '0346-5592321', '2022-08-16', 3682, '15602-4834464-1', '03', 'GHSS Chitor', '6th', '', 1),
(2268, 'Muhammad Arif', 'Naseeb Zada', 'Male', '2011-04-13', '0343-5297620', '2022-08-16', 3683, '15602-0399639-3', '03', 'GHSS Chitor', '6th', '', 1),
(2269, 'Maaz Khan', 'Ghani Rahman ', 'Male', '2011-06-20', '0344-0920188', '2022-08-16', 3684, '15602-9075176-5', '03', 'GHSS Chitor', '6th', '', 1),
(2271, 'Muhammad Yaseen', 'Hassan Jan', 'Male', '2008-04-03', '0344-9617651', '2022-08-22', 3726, '15602-0245532-9', '15602-', 'GHSS Chitor', '7th', '', 1),
(2272, 'Faisal', 'Nasar Khan', 'Male', '2009-03-01', '0340-6795726', '2022-08-22', 3718, '15602-1995074-3', '15602-', 'GHSS Chitor', '7th', '', 1),
(2273, 'Muhammad Khan', 'Musa Khan', 'Male', '2009-12-10', '0342-5474863', '2022-08-22', 3717, '15602-6065654-7', '15602-', 'GHSS Chitor', '7th', '', 1),
(2281, 'Imdadullah', 'Sher Zaman', 'Male', '2009-09-05', '0346-9474916', '2022-08-17', 3721, '15602-02853-9', '15602-', 'GHSS Chitor', '8th', '', 1),
(2282, 'Adnan Jan', 'Asmat Ali', 'Male', '2009-11-05', '0345-9312390', '2022-08-17', 3723, '15602-0245606-1', '15602-', 'GHSS Chitor', '8th', '', 1),
(2283, 'Sajjad Ali', 'Abdul Satar', 'Male', '2005-04-06', '03', '2022-08-17', 3719, '15602-', '15602-', 'GHSS Chitor', '8th', '', 1),
(2284, 'Said Rahim', 'Gul Rashid', 'Male', '2008-03-15', '0349-3522395', '2022-08-17', 3724, '15602-9707233-3', '15602-', 'GHSS Chitor', '8th', '', 1),
(2285, 'Abdullah', 'Feroz Jan', 'Male', '2009-01-15', '03', '2022-08-25', 3728, '15602-', '15602-', 'GHSS Chitor', '8th', '', 1),
(2286, 'Rahmat Ali', 'Ashgar Ali', 'Male', '2009-03-06', '03', '2022-11-02', 3730, '15602-', '15602-', 'GHSS Chitor', '8th', '', 1),
(2287, 'Rahmat Ali', 'Pervaish', 'Male', '2009-02-15', '03', '2022-11-02', 3729, '15602-', '15602-', 'GHSS Chitor', '8th', '', 1),
(3434, 'Waqas Ahmad', 'ahmad', 'Female', '1900-01-01', '03', '2023-04-06', 34347, '15602-', '15602-', 'GHSS Chitor', '6th', '', 1),
(3435, 'Naddem', 'Khan', 'Male', '1900-01-01', '03', '2023-04-07', 3435, '15602-', '15602-', 'GHSS Chitor', '6th', '', 1),
(21610, 'Umar Wahid', 'Zahir  Shah', 'Male', '2010-07-20', '0345-9014774', '2021-07-12', 3626, '15602-0246382-3', '', 'GHSS Chitor', '7th', '', 1),
(21611, 'Muhammad Aziz Ur Rahman', 'Muhammad Younas', 'Male', '2009-06-10', '0344-9662527', '2021-07-12', 3627, '15602-0380599-5', '', 'GHSS Chitor', '7th', '', 1),
(21612, 'Sikandar Hayat', 'Umar Hayat', 'Male', '2009-09-17', '0342-8977489', '2021-07-12', 3628, '15602-3890440-1', '', 'GHSS Chitor', '7th', '', 1),
(21613, 'Waqas Ahmad', 'Gulab Sher', 'Male', '2008-01-10', '03', '2021-07-12', 3629, '', '', 'GHSS Chitor', '7th', '', 0),
(21614, 'Arshad Ali', 'Umar Muhammad', 'Male', '2007-05-21', '0348-9815673', '2021-07-12', 3630, '15602-0302201-3', '', 'GHSS Chitor', '7th', '', 1),
(21615, 'Kifayat Ullah', 'Sardar Ali', 'Male', '2011-09-26', '0342-8281171', '2021-07-12', 3631, '15602-2558552-5', '', 'GHSS Chitor', '7th', '', 1),
(21616, 'Amir Zeb', 'Amir Zareen', 'Male', '2010-01-05', '0344-9656577', '2021-07-12', 3632, '15602-0423569-5', '', 'GHSS Chitor', '7th', '', 1),
(21617, 'Muhammad Saleem', 'Abdul Wahab', 'Male', '2007-04-15', '0341-8057772', '2021-07-12', 3633, '15602-4957931-3', '', 'GHSS Chitor', '6th', '', 1),
(21618, 'Muhammad Sohail', 'Rafiullah Jan', 'Male', '2010-04-01', '0341-9301369', '2021-07-12', 3634, '15602-0266647-9', '', 'GHSS Chitor', '7th', '', 1),
(21619, 'Yahya Khan', 'Rahim Zada', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '6th', '', 0),
(21620, 'Sher Ali', 'Hazrat Rahman', 'Male', '2008-04-04', '0946-865281', '2021-07-12', 3636, '15602-4251254-1', '', 'GHSS Chitor', '7th', '', 1),
(21621, 'Luqman Khan', 'Lal Muhammad', 'Male', '2009-01-03', '0340-6129330', '2021-07-12', 3637, '15602-1408925-9', '', 'GHSS Chitor', '7th', '', 1),
(21622, 'Zain Ullah', 'Rahmat Ali', 'Male', '2009-04-06', '0343-9400624', '2021-07-12', 3638, '15602-1167926-5', '', 'GHSS Chitor', '7th', '', 1),
(21623, 'Ihsan Ullah', 'Umar Zada', 'Male', '2010-04-10', '0341-9135445', '2021-07-12', 3639, '15602-1167926-5', '', 'GHSS Chitor', '7th', '', 1),
(21624, 'Inam Ullah', 'Umar Zada', 'Male', '2009-04-18', '0341-9135445', '2021-07-12', 3640, '15602-0421664-3', '', 'GHSS Chitor', '7th', '', 1),
(21625, 'Abu Bakar', 'Haya Khan', 'Male', '2010-01-07', '0348-0154731', '2021-07-12', 3641, '15602-5572901-3', '', 'GHSS Chitor', '7th', '', 1),
(21626, 'Ihsan Ullah', 'Sayed Awlia Bacha', 'Male', '2010-04-15', '0348-9104427', '2021-07-12', 3642, '15602-0246371-9', '', 'GHSS Chitor', '7th', '', 1),
(21627, 'Hazrat Ali', 'Akbar Khan', 'Male', '2010-04-15', '0344-3183086', '2021-07-12', 3643, '15602-1803313-7', '', 'GHSS Chitor', '7th', '', 1),
(21628, 'Hazrat Hussain', 'Bakht Rawan', 'Male', '2010-04-13', '0346-9629774', '2021-07-12', 3644, '15602-5743656-1', '', 'GHSS Chitor', '7th', '', 1),
(21629, 'Muhammad Abu Bakar', 'Ashraf Ali', 'Male', '2010-04-10', '0347-7494613', '2021-07-12', 3645, '15602-0474567-1', '', 'GHSS Chitor', '7th', '', 1),
(21630, 'Najib Ullah', 'Azim Khan', 'Male', '2009-04-02', '0348-5223121', '2021-07-12', 3646, '15602-0239158-1', '', 'GHSS Chitor', '7th', '', 1),
(21631, 'Shahzad Khan', 'Amir Noshad', 'Male', '2009-04-08', '0342-2257022', '2021-07-12', 3647, '15602-0472326-3', '', 'GHSS Chitor', '7th', '', 1),
(21632, 'Asad Khan', 'Palash Khan', 'Male', '2010-04-12', '0324-9828231', '2021-07-12', 3648, '1562-4251254-1', '', 'GHSS Chitor', '7th', '', 1),
(21633, 'Shakir Ullah', 'Jahan Zar', 'Male', '2008-04-10', '0346-9994132', '2021-07-12', 3649, '15602-4644585-1', '', 'GHSS Chitor', '6th', '', 1),
(21634, 'Asmat Ali ', 'Akbar Ali Khan', 'Male', '2009-02-07', '0346-1954364', '2021-07-12', 3650, '15602-4551654-1', '', 'GHSS Chitor', '6th', '', 1),
(21635, 'Khanadan', 'Said Gulab', 'Male', '2009-09-09', '0346-3398172', '2021-07-12', 3651, '15602-0247005-7', '', 'GHSS Chitor', '7th', '', 1),
(21636, 'Burhan Khan', 'Gul Wahid', 'Male', '2010-01-01', '0347-0564402', '2021-07-12', 3652, '15602-5392323-9', '', 'GHSS Chitor', '7th', '', 1),
(21637, 'Sardar Hussain', 'Jamrooz', 'Male', NULL, '0341-4329029', NULL, NULL, NULL, NULL, 'GHSS Chitor', '6th', '', 0),
(21638, 'Anwar Zeb', 'Umar Zeb', 'Male', '2008-12-30', '0342-0087013', '2021-07-15', 3654, '15602-0259811-9', '', 'GHSS Chitor', '6th', '', 1),
(21639, 'Fawad Ali', 'Bakht Rawan', 'Male', '2008-01-10', '0347-9117757', '2021-07-15', 3655, '15602-8165318-3', '', 'GHSS Chitor', '6th', '', 1),
(21640, 'Muhammad Abrar', 'Bakht Zada', 'Male', '2008-01-18', '0349-9459060', '2021-07-15', 3656, '15602-9046735-1', '', 'GHSS Chitor', '6th', '', 1),
(21641, 'Muhammad Khan', 'Bado', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(21642, 'Ihsan Ali', 'Muhammad Ishaq', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(21643, 'Akhtar Muhammad', 'Yousaf Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(21644, 'Bahram Khan', 'Alam Khan', 'Male', NULL, '0342-9863522', NULL, NULL, NULL, NULL, 'GHSS Chitor', '6th', '', 0),
(21645, 'Abid Ullah', 'Izat Gul', 'Male', '2008-04-01', '0345-2366041', '2021-07-27', 3663, '15602-8237433-9', '', 'GHSS Chitor', '7th', '', 1),
(21646, 'Rahman Ali ', 'Liaqat Ali', 'Male', NULL, '0341-9294787', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(21647, 'Jamal Said', 'Muhammad', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(21648, 'Muhammad Riaz', 'Hukam Khan', 'Male', '2010-03-28', '0340-9482933', '2021-08-07', 3672, '15602-9458411-7', '', 'GHSS Chitor', '7th', '', 1),
(21649, 'Muhammad Zakir Ullah', 'Habib Ullah', 'Male', '2009-12-04', '0345-1575751', '2021-08-12', 3673, '15701-1232030-3', '', 'GHSS Chitor', '7th', '', 1),
(21650, 'Habib Ullah', 'Umar Gul', 'Male', '2009-09-01', '0340-9012365', '2021-08-13', 3674, '15602-024637-7', '', 'GHSS Chitor', '7th', '', 1),
(21711, 'Arshad Ali', 'Amjad Ali', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(21712, 'Muhammad Salman', 'Bakht Rawan', 'Male', '2008-04-05', '0342-9722716', '2019-04-11', 3514, '15602-0915903-9', '', 'GHSS Chitor', '8th', '', 1),
(21713, 'Wajid Ali', 'Rozi Khan', 'Male', '2008-04-01', '0347-4353146', '2019-04-11', 3516, '1562-1413307-1', '', 'GHSS Chitor', '7th', '', 1),
(21714, 'Sanaullah', 'Iqbal Zareen', 'Male', '2006-04-01', '0349-8321466', '2019-04-11', 3517, '15602-0351106-3', '', 'GHSS Chitor', '8th', '', 1),
(21715, 'Sultan Ali', 'Bakht Rawan', 'Male', '2004-03-10', '0347-9117757', '2019-04-13', 3527, '15602-8165318-3', '', 'GHSS Chitor', '7th', '', 1),
(21716, 'Haroon Khan', 'Fateh Khan', 'Male', '2006-09-18', '0334-9338245', '2019-04-10', 3493, '15602-0251107-3', '', 'GHSS Chitor', '8th', '', 1),
(21717, 'Abu Bakar Khan', 'Muhammad Ali', 'Male', '2010-06-06', '0343-9303005', '2019-10-15', 3546, '15602-4680310-1', '', 'GHSS Chitor', '8th', '', 1),
(21718, 'Altaf Hussain', 'Shah Hussain', 'Male', '2008-01-25', '0345-2702889', '2019-10-15', 3547, '15602-0311680-5', '', 'GHSS Chitor', '8th', '', 1),
(21719, 'Muhammad Kareem', 'Abdul Kareem', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '8th', '', 0),
(21721, 'Hazrat Bilal', 'Ibrahim', 'Male', '2007-03-10', '0346-0974415', '2020-09-15', 3572, '15602-0245764-1', '', 'GHSS Chitor', '8th', '', 1),
(21722, 'Muhammad Said', 'Umar Said', 'Male', '2008-09-14', '0341-1190062', '2020-09-15', 3571, '15602-0345186-9', '', 'GHSS Chitor', '8th', '', 1),
(21723, 'Abdur Rahman', 'Bakht Baydar', 'Male', '2007-05-01', '0341-5049936', '2020-09-15', 3573, '15602-2438015-9', '', 'GHSS Chitor', '8th', '', 1),
(21724, 'Muhammad Shahid', 'Habib Ur Rahman', 'Male', '2006-03-31', '0343-2240767', '2020-09-15', 3575, '15602-4472854-1', '', 'GHSS Chitor', '7th', '', 1),
(21725, 'Shah Fayaz', 'Isa Khan', 'Male', '2010-03-10', '03429286562', '2020-09-15', 3576, '15602-1820364-5', '', 'GHSS Chitor', '8th', '', 1),
(21726, 'Irfan Ullah', 'Bahram Khan', 'Male', '2008-01-10', '0349-7304235', '2020-09-15', 3577, '904010-108923-5', '', 'GHSS Chitor', '8th', '', 0),
(21727, 'Muhammad Maaz', 'Muhammad Shah', 'Male', '2008-01-13', '0343-1974586', '2020-09-15', 3578, '15602-0245822-7', '', 'GHSS Chitor', '8th', '', 1),
(21728, 'Muhammad Zahid', 'Muhammad Yaqoob', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '8th', '', 0),
(21729, 'Muhammad Shoaib', 'Khalid', 'Male', '2007-01-01', '0343-5941250', '2020-09-15', 3580, '15602-0284869-3', '', 'GHSS Chitor', '8th', '', 1),
(21810, 'Jamil Khan', 'Bakht Fareed', 'Male', '2007-04-04', '0344-5187324', '1900-01-01', 4186, '1602-0501851-3', '', 'GHSS Chitor', '9th A', '', 1),
(21811, 'Ikram Ullah', 'Amir Noshad', 'Male', '2008-04-20', '0346-9206687', '1900-01-01', 4187, '15602-0472326-3', '', 'GHSS Chitor', '9th A', '', 1),
(21812, 'Ilyas Khan', 'Nawab Khan', 'Male', '2006-06-05', '0347-9529785', '1900-01-01', 4188, '', '', 'GHSS Chitor', '9th A', '', 1),
(21813, 'Abdullah', 'Abdul Zahir', 'Male', '2008-03-04', '0347-4127119', '1900-01-01', 4189, '15602-8606950-7', '', 'GHSS Chitor', '9th A', '', 1),
(21814, 'Rahmat Ali', 'Gul Zareen', 'Male', '2004-04-19', '0348-1959293', '1900-01-01', 4190, '15602-0262064-7', '', 'GHSS Chitor', '9th A', '', 1),
(21815, 'Hazrat Maaz', 'Fazal Ghani', 'Male', '2008-11-30', '0333-9496904', '1900-01-01', 4191, '15602-6506276-1', '', 'GHSS Chitor', '9th A', '', 1),
(21816, 'Muhammad Majid', 'Rahmat Ullah', 'Male', '2008-04-20', '0346-1954329', '1900-01-01', 4216, '15602-8273242-7', '', 'GHSS Chitor', '9th A', '', 1),
(21817, 'Hazrat Ali', 'Izat Muhammad', 'Male', '2006-05-04', '0342-8978561', '1900-01-01', 4192, '15602-0250620-5', '', 'GHSS Chitor', '9th A', '', 1),
(21818, 'Muhammad Ayaz', 'Bakhti Gul', 'Male', '2007-03-05', '0342-1994726', '1900-01-01', 4193, '15602-0458302-1', '', 'GHSS Chitor', '9th A', '', 1),
(21819, 'Hamza Hussain', 'Bakht Hussain', 'Male', '2008-02-15', '0346-9431045', '1900-01-01', 4194, '15602-1006729-1', '', 'GHSS Chitor', '9th A', '', 1),
(21820, 'Awais Jan', 'Rahmat Jan', 'Male', '2007-04-30', '0313-2004284', '1900-01-01', 4195, '15101-1964404-3', '', 'GHSS Chitor', '9th A', '', 1),
(21821, 'Ubaid Ullah', 'Afzal Shah', 'Male', '2008-01-30', '0342-9724520', '1900-01-01', 4196, '15602-8454256-9', '', 'GHSS Chitor', '9th A', '', 0),
(21822, 'Muhammad Abu Bakar Khan', 'Amir Haidar', 'Male', '2007-02-04', '0342-9621894', '1900-01-01', 4215, '15602-0423515-7', '', 'GHSS Chitor', '9th A', '', 1),
(21823, 'Sayed Muhammad Waqas', 'Taj Malook', 'Male', '2008-02-09', '0334-3553351', '1900-01-01', 4197, '15602-0290262-7', '', 'GHSS Chitor', '9th A', '', 1),
(21824, 'Aftab Ali', 'Shah Bali Khan', 'Male', '2008-01-07', '0340-0934191', '1900-01-01', 4198, '15602-2311125-3', '', 'GHSS Chitor', '9th A', '', 1),
(21825, 'Muhammad Yaseen', 'Bakhram Khan', 'Male', '1900-01-01', '0323-9243734', '1900-01-01', 4199, '', '', 'GHSS Chitor', '9th A', '', 0),
(21826, 'Izhar Khan', 'Ayub Khan', 'Male', '2008-01-08', '0342-9605966', '1900-01-01', 4200, '15602-0532186-3', '', 'GHSS Chitor', '9th A', '', 1),
(21827, 'Muhammad Rizwan', 'Aqal Zeb', 'Male', '2008-04-04', '0342-9617419', '1900-01-01', 4201, '15602-0398601-5', '', 'GHSS Chitor', '9th A', '', 1),
(21828, 'Imran Ali', 'Gul Far Ali', 'Male', '2008-03-02', '0342-8687533', '1900-01-01', 4202, '15602-275968-7', '', 'GHSS Chitor', '9th A', '', 1),
(21829, 'Hussain Ali', 'Umar Gul', 'Male', '2008-04-10', '0344-4040233', '1900-01-01', 4203, '15602-6709584-7', '', 'GHSS Chitor', '9th A', '', 1),
(21830, 'Barkat Ali', 'Umar', 'Male', '2008-02-02', '0349-3551351', '1900-01-01', 4204, '15602-3508281-5', '', 'GHSS Chitor', '9th A', '', 1),
(21831, 'Imtiaz Khan', 'Bakht Nazir', 'Male', '2008-01-01', '0340-9279252', '1900-01-01', 4205, '15602-3871354-9', '', 'GHSS Chitor', '9th A', '', 1),
(21832, 'Zohaib Khan', 'Bakht Nazir', 'Male', '2007-01-15', '0340-9279252', '1900-01-01', 4206, '15602-3871354-8', '', 'GHSS Chitor', '9th A', '', 1),
(21833, 'Muhammad Hasnain', 'Muhammad Iqbal', 'Male', '2008-04-01', '0342-9613652', '1900-01-01', 4207, '15602-0417372-1', '', 'GHSS Chitor', '9th A', '', 1),
(21834, 'Abdur Rahman', 'Ali Rahman', 'Male', '2007-03-03', '0346-3021839', '1900-01-01', 4208, '15602-0423448-9', '', 'GHSS Chitor', '9th A', '', 1),
(21835, 'Inam Ullah', 'Amir Rahman', 'Male', '2006-02-01', '0342-9089350', '1900-01-01', 4209, '15602-5311629-5', '', 'GHSS Chitor', '9th A', '', 1),
(21836, 'Muhammad Sadiq', 'Aman Ullah', 'Male', '2008-04-01', '0306-8021642', '1900-01-01', 4210, '15602-0245606-1', '', 'GHSS Chitor', '9th A', '', 1),
(21837, 'Muhammad Hussain', 'Muhammad Towkal', 'Male', '2008-03-05', '0342-3060152', '1900-01-01', 4211, '15602-0285145-5', '', 'GHSS Chitor', '9th A', '', 1),
(21838, 'Muhammad Ibrahim', 'Amir Subhan', 'Male', '2008-02-08', '0344-9858202', '2020-10-02', 3606, '15602-0251095-7', '', 'GHSS Chitor', '8th', '', 1),
(21839, 'Abu Bakar Sadiq', 'Shawkat Ali', 'Male', '2008-01-05', '0341-1581543', '1900-01-01', 4212, '15602-0284117-3', '', 'GHSS Chitor', '9th A', '', 1),
(21840, 'Inam Ullah', 'Umar Rahman', 'Male', '2008-04-04', '0342-9666729', '1900-01-01', 4213, '15602-4624613-3', '', 'GHSS Chitor', '9th A', '', 1),
(21841, 'Irfan Ullah', 'Bahroz Khan', 'Male', '2006-03-25', '0348-5713115', '1900-01-01', 4214, '15602-3251389-9', '', 'GHSS Chitor', '9th A', '', 1),
(21842, 'Waqas Khan', 'Asmat Ali', 'Male', '2008-02-12', '0345-0597614', '2021-07-15', 3664, '15602-2860341-3', '', 'GHSS Chitor', '8th', '', 1),
(22292, 'Fazal Rashid', 'Bakht Yaar', 'Male', '2007-01-01', '03', '2022-11-07', 4276, '15602-', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22610, 'Rahan Shah', 'Muhammad Parveez', 'Male', '2011-06-19', '0344-9689724', '2022-08-16', 3685, '15602-0351662-9', '03', 'GHSS Chitor', '6th', '', 1),
(22611, 'Usman Ali', 'Abdul Wahid', 'Male', '2011-04-12', '0345-6662122', '2022-08-16', 3686, '156027030394-7', '03', 'GHSS Chitor', '6th', '', 1),
(22612, 'Akhtar Hussain', 'Fazal wahid', 'Male', '2011-04-02', '0342-9845137', '2022-08-16', 3687, '15602-2677743-1', '03', 'GHSS Chitor', '6th', '', 1),
(22613, 'Navid Khan', 'Syed Jalil', 'Male', '2010-12-02', '0344-3085547', '2022-08-16', 3688, '15602-0246072-7', '03', 'GHSS Chitor', '6th', '', 1),
(22614, 'Arbaz Khan', 'Muhammad Khan', 'Male', '2006-02-01', '0344-9770104', '2022-08-16', 3689, '15602-0516499-3', '03', 'GHSS Chitor', '6th', '', 1),
(22615, 'Muhammad Waqas', 'Muhammad Ismail', 'Male', '2011-03-05', '0349-9355375', '2022-08-16', 3690, '15602-4331383-3', '03', 'GHSS Chitor', '6th', '', 1),
(22616, 'Rafiullah', 'Behram Khan', 'Male', '2009-03-01', '0349-7304235', '2022-08-16', 3691, '904010-108923-5', '03', 'GHSS Chitor', '6th', '', 1),
(22617, 'Hidayat Ullah', 'Gul Rahman', 'Male', '2010-04-01', '03420086462', '2022-08-16', 3692, '1560202166939', '03', 'GHSS Chitor', '6th', '', 1),
(22618, 'Muhammad Islam', 'Shams ul bareez', 'Male', '2010-03-10', '03470193717', '2022-08-16', 3693, '15602-72337619', '03', 'GHSS Chitor', '6th', '', 1),
(22619, 'Amir Hamza', 'Amir Rahman', 'Male', '2010-03-29', '0342-2249085', '2022-08-16', 3694, '15602-0478411-7', '03', 'GHSS Chitor', '6th', '', 1),
(22620, 'Asad Khan', 'Sarfarz Khan', 'Male', '2011-01-01', '0342-9841375', '2022-08-16', 3695, '15602-8374975-7', '03', 'GHSS Chitor', '6th', '', 1),
(22621, 'Rahmatullah', 'Umar Rashid', 'Male', '2010-04-14', '0346-3879998', '2022-08-16', 3996, '15101-5896784-1', '03', 'GHSS Chitor', '6th', '', 1),
(22622, 'Sanullah', 'Anwar Rashid', 'Male', '2010-04-13', '0342-1595440', '2022-08-16', 3697, '15101-8937726-9', '03', 'GHSS Chitor', '6th', '', 1),
(22623, 'Muhammad Riaz', 'Gul Zamin', 'Male', '2010-03-31', '0348-0153753', '2022-08-16', 3698, '15602-0277054-9', '03', 'GHSS Chitor', '6th', '', 1),
(22624, 'Muhammad Usman', 'Amir Dost Khan', 'Male', '2010-04-14', '0341-5723115', '2022-08-16', 3699, '15602-9080482-1', '03', 'GHSS Chitor', '6th', '', 1);
INSERT INTO `students_info` (`Roll_No`, `Name`, `FName`, `Gender`, `Dob`, `Mobile_No`, `Admission_Date`, `Admission_No`, `Father_Cnic`, `Student_Form_B`, `School`, `Class`, `Class_Position`, `Status`) VALUES
(22625, 'Muhammad Muslim Khan', 'Sardar Ali', 'Male', '2010-04-04', '0348-4404681', '2022-08-16', 3700, '15602-0396111-7', '03', 'GHSS Chitor', '6th', '', 1),
(22626, 'Nisar Ahmad', 'Itbar Gul', 'Male', '2010-04-10', '0345-5446340', '2022-08-16', 3701, '15602-4810412-7', '03', 'GHSS Chitor', '6th', '', 1),
(22627, 'Muhammad Haroon', 'Sar far Ali', 'Male', '2011-04-03', '0343-9410062', '2022-08-16', 3702, '15602-1487438-3', '03', 'GHSS Chitor', '6th', '', 1),
(22628, 'Yasir Ali', 'Umar Zarin', 'Male', '2011-03-04', '0349-7312812', '2022-08-16', 3703, '15602-59700197', '03', 'GHSS Chitor', '6th', '', 1),
(22629, 'Muhammad Mobeen', 'Iqbal Zarin', 'Male', '2011-03-04', '0349-8321466', '2022-08-16', 3704, '15602-0351106-3', '15602-', 'GHSS Chitor', '6th', '', 1),
(22630, 'Maaz Ali', 'Bakht Subhan', 'Male', '2010-04-02', '0349-9093812', '2022-08-16', 3705, '15602-6485744-7', '15602-', 'GHSS Chitor', '6th', '', 1),
(22631, 'Kashif Rashid', 'Muhammad Ishaq', 'Male', '2011-04-04', '0342-9638859', '2022-08-16', 3706, '15602-0244886-3', '15602-', 'GHSS Chitor', '6th', '', 1),
(22632, 'Samiullah', 'Anwar Rashid', 'Male', '2011-04-03', '0346-3879998', '2022-08-16', 3707, '15101-5896784-1', '15602-', 'GHSS Chitor', '6th', '', 1),
(22633, 'Muhammad Fayaz', 'Bakhti Gul', 'Male', '2011-08-06', '0346-2256429', '2022-08-16', 3708, '15602-82407809', '15602-', 'GHSS Chitor', '6th', '', 1),
(22634, 'Aziz Khan', 'Sher Zaman', 'Male', '2010-04-20', '0345-1507059', '2022-08-16', 3709, '15602-3010088-7', '15602-', 'GHSS Chitor', '6th', '', 1),
(22635, 'Aftab Alam', 'Muhammad Alam', 'Male', '2006-05-10', '0344-9097772', '2022-08-16', 3710, '15602-9424423-1', '15602-', 'GHSS Chitor', '6th', '', 1),
(22636, 'Wasil Khan', 'Umar Muhammad', 'Male', '2010-03-02', '0305-9618026', '2022-08-16', 3711, '15602-02549677', '15602-', 'GHSS Chitor', '6th', '', 1),
(22637, 'Ahmad Khan', 'Bahadar Khan', 'Male', '2010-01-01', '0320-9113284', '2022-08-16', 3712, '15602-1082711-9', '15602-', 'GHSS Chitor', '6th', '', 1),
(22638, 'Wahidullah', 'Abdul Hanan', 'Male', '2008-03-05', '0344-9858202', '2022-08-16', 3713, '15602-0495596-1', '15602-', 'GHSS Chitor', '6th', '', 1),
(22639, 'Abid Ur Rahman', 'Amir Zada', 'Male', '2010-05-10', '0348-1304251', '2022-08-16', 3714, '15602-7516825-3', '15602-', 'GHSS Chitor', '6th', '', 1),
(22640, 'Amjad Ali', 'Attaullah', 'Male', '2009-04-01', '0348-9470217', '2022-08-16', 3715, '15703-1118056-5', '15602-', 'GHSS Chitor', '6th', '', 1),
(22641, 'Sudias Ahmad', 'Muhammad Nawab', 'Male', '2010-04-10', '0346-9444184', '2022-08-16', 3716, '15602-0534859-7', '15602-', 'GHSS Chitor', '6th', '', 1),
(22642, 'Roshan Ali', 'Noor Zada', 'Male', '2011-06-10', '0343-5297620', '2022-08-16', 3720, '15602-0320234-6', '15602-', 'GHSS Chitor', '6th', '', 1),
(22643, 'Fayaz Ahmad', 'Bahadar', 'Male', '2010-02-14', '0341-9185833', '2022-08-16', 3722, '15602-0247458-9', '15602-', 'GHSS Chitor', '6th', '', 1),
(22644, 'Habibullah', 'Tota', 'Male', '2010-03-10', '03448176820', '2022-08-16', 3725, '15602-0245515-1', '15602-', 'GHSS Chitor', '6th', '', 0),
(22645, 'Bilal Ahmad', 'Yousaf', 'Male', '2009-08-15', '0342-2864438', '2022-08-16', 3727, '15602-0246061-7', '15602-', 'GHSS Chitor', '6th', '', 1),
(22911, 'Abdul Hamid', 'Abdul Satter', 'Male', '2006-09-16', '0345-9279916', '2022-08-24', 4217, '15602-', '15602-', 'GHSS Chitor', '9th A', '', 1),
(22912, 'Imdadullah', 'Sher Malik', 'Male', '2008-04-22', '0349-1117870', '2022-08-24', 4219, '15602-0350674-5', '15602-', 'GHSS Chitor', '9th A', '', 1),
(22913, 'Haneefullah', 'Ikramullah', 'Male', '2008-04-15', '0349-3544385', '2022-08-24', 4220, '15602-50799759', '15602-', 'GHSS Chitor', '9th A', '', 1),
(22914, 'Aziz ur Rahman', 'Bakht Zada', 'Male', '1900-01-01', '0343-7637722', '2022-08-24', 4221, '15602-0275825-5', '15602-', 'GHSS Chitor', '9th A', '', 0),
(22915, 'Muhammad Mehran ', 'Rahmat Ali', 'Male', '2008-04-07', '0348-6785531', '2022-08-24', 4222, '15602-1643164-3', '15602-', 'GHSS Chitor', '9th A', '', 1),
(22916, 'Adnan Khan', 'Amir Zeb', 'Male', '2008-03-05', '0348-6785531', '2022-08-24', 4223, '15602-0246891-3', '15602-', 'GHSS Chitor', '9th A', '', 1),
(22917, 'Mohsin Azim', 'Fazal Azim', 'Male', '2008-09-16', '0344-1925552', '2022-08-24', 4265, '15602-02770905', '15602-', 'GHSS Chitor', '9th A', '', 1),
(22920, 'waqas khan', 'ahmad khan', 'Male', '2023-03-01', '03339494242', '2023-03-05', 789654, '15602-3069132-8', '15602-3069132-9', 'GHSS Chitor', '6th', '', 0),
(22921, 'Hussain Ali', 'Hayat Khan', 'Male', '2008-09-06', '0342-1964643', '2022-08-17', 4224, '15602-42671035', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22922, 'Shafiullah', 'Fazal Rahman', 'Male', '2007-04-03', '0348-9175972', '2022-08-17', 4225, '15602-1515519-5', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22923, 'Saeed Khan', 'Ahmad Sultan', 'Male', '2008-03-11', '0344-9854882', '2022-08-17', 4226, '15602-', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22924, 'Muhammad Hassan', 'Bakht Farid Khan', 'Male', '2007-03-20', '0314-9053035', '2022-08-17', 4227, '15602-0282403-3', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22925, 'Khalilullah', 'Gul Khan', 'Male', '2006-04-01', '0345-5547948', '2022-08-17', 4228, '15602-7134926-9', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22926, 'Ahsanullah', 'Rahmani Gul', 'Male', '2008-05-10', '0343-9120812', '2022-08-17', 4229, '15602-0894998-9', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22927, 'Muhammad Ishaq', 'Yousaf Khan', 'Male', '2008-04-03', '0345-7779478', '2022-08-17', 4230, '15602-', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22928, 'Awais Khan', 'Sharaz', 'Male', '2007-12-05', '0345-3459465', '2022-08-17', 4231, '15602-9145313-7', '15602-', 'GHSS Chitor', '9th B', '', 1),
(22929, 'Hamidullah', 'Awaz Khan', 'Male', '2007-03-30', '0340-9412209', '2022-08-17', 4232, '15602-1246645-1', '15602-', 'GHSS Chitor', '9th B', '', 1),
(210729, 'Asim Khan', 'Hayat Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(210730, 'Tawseef Khan', 'Hayat Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(217110, 'Adnan Khan', 'Aziz Khan', 'Male', '2006-05-10', '+97154315369', '2020-09-15', 3549, '15602-0257574-7', '', 'GHSS Chitor', '7th', '', 1),
(217111, 'Sadiq Ur Rahman', 'Fazal Rahman', 'Male', '2008-04-17', '0342-2243085', '2019-10-15', 3550, '15602-8208537-5', '', 'GHSS Chitor', '8th', '', 1),
(217112, 'Muhsin Ali', 'Ibrahim', 'Male', '2010-03-10', '0340-6667667', '2019-10-15', 3551, '15602-0290925-1', '', 'GHSS Chitor', '8th', '', 1),
(217113, 'Sanaullah', 'Shah Wazir Khan', 'Male', '2009-03-03', '0340-9735645', '2019-10-15', 3552, '15602-0461743-1', '', 'GHSS Chitor', '8th', '', 1),
(217114, 'Muhammad Sadeeq', 'Fazal Wahid', 'Male', '2008-04-14', '0334-9318327', '2019-10-15', 3553, '15602-0250652-7', '', 'GHSS Chitor', '8th', '', 1),
(217115, 'Muhammad Ismail', 'Bakht Rawan', 'Male', '2005-03-10', '0342-9638859', '2019-10-15', 3554, '15602-0244886-3', '', 'GHSS Chitor', '8th', '', 0),
(217116, 'Ihsan Ullah', 'Bakht Rawan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '8th', '', 0),
(217117, 'Sardar Hussain', 'Iqbal Hussain', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '7th', '', 0),
(217118, 'Khalil Ur Rahman', 'Said Bashar', 'Male', '2009-09-02', '0347-678726', '2020-09-15', 3558, '15601-3129932-5', '', 'GHSS Chitor', '8th', '', 1),
(217119, 'Ihsan Ullah', 'Amir Gulab', 'Male', '2006-02-01', '0344-2826350', '2020-09-15', 3559, '15602-0445118-7', '', 'GHSS Chitor', '7th', '', 1),
(217120, 'Muhammad Mehran', 'Rahmat Ullah', 'Male', '2004-04-20', '0346-1954329', '2008-09-15', 3561, '15602-8273242-7', '', 'GHSS Chitor', '8th', '', 1),
(217121, 'Umar Khitab', 'Fazal Mowla', 'Male', '2008-04-25', '0347-9696971', '2008-09-15', 3562, '15602-5284492-7', '', 'GHSS Chitor', '8th', '', 1),
(217122, 'Sher Bacha', 'Dost Muhammad Khan', 'Male', '2008-06-01', '0343-1195916', '2020-09-15', 3563, '15602-0494167-3', '', 'GHSS Chitor', '8th', '', 1),
(217123, 'Shakil', 'Barkat Ali', 'Male', '2007-03-02', '0347-6731023', '2020-09-15', 3564, '15602-2520998-3', '', 'GHSS Chitor', '8th', '', 1),
(217124, 'Abu Bakar', 'Amin Gul', 'Male', '2009-01-01', '0343-9303005', '2020-09-15', 3565, '15602-0396137-5', '', 'GHSS Chitor', '8th', '', 1),
(217125, 'Hasnain Hameed', 'Hameed Ullah', 'Male', '2007-04-05', '0345-9455976', '2020-09-23', 3597, '15602-0513783-1', '', 'GHSS Chitor', '7th', '', 1),
(217126, 'Farhan Ali', 'Aslam Khan', 'Male', '2007-04-10', '0346-8072566', '2020-09-28', 3601, '15602-3490690-7', '0346-8072566', 'GHSS Chitor', '7th', '', 1),
(217127, 'Hazrat Ullah', 'Pardil Khan', 'Male', '2004-06-02', '0315-9048282', '2020-10-02', 3605, '15602-0532813-1', '', 'GHSS Chitor', '8th', '', 1),
(217128, 'Shafiullah', 'Ali Rahman', 'Male', '2008-04-05', '03', '2020-10-02', 3607, '', '', 'GHSS Chitor', '8th', '', 1),
(217129, 'Usman Ghani', 'Said Ali', 'Male', '2008-03-04', '0347-9684926', '2020-10-02', 3611, '15602-2496098-1', '', 'GHSS Chitor', '8th', '', 1),
(217210, 'Shoaib Akhtar', 'Khadim Shah', 'Male', '2009-12-13', '0321-9791344', '2009-12-13', 3583, '15602-5891918-7', '', 'GHSS Chitor', '8th', '', 1),
(217211, 'Muhammad Shoaib', 'Umar Wahab', 'Male', '2008-05-20', '0333-3477125', '2020-09-15', 3586, '15602-0246374-7', '', 'GHSS Chitor', '8th', '', 1),
(217212, 'Muhammad Talha', 'Bakht Namir', 'Male', '2009-04-07', '0347-5169731', '2020-09-15', 3587, '15602-3171142-3', '', 'GHSS Chitor', '8th', '', 1),
(217213, 'Azizullah', 'Fazal Subhan', 'Male', '2007-04-05', '0342-9827797', '0220-09-15', 3588, '15602-1644273-7', '', 'GHSS Chitor', '8th', '', 1),
(217214, 'Ahmad Hussain', 'Alamgir', 'Male', '2007-11-21', '0342-9467482', '2020-09-15', 3589, '15602-0246993-9', '', 'GHSS Chitor', '8th', '', 1),
(217215, 'Nayab Hussain', 'Jehangir Mian', 'Male', '2009-03-23', '0342-9836245', '2020-09-15', 3590, '15602-0309262-7', '', 'GHSS Chitor', '8th', '', 1),
(217216, 'Muhammad Hamza', 'Umar Zameen', 'Male', '2009-04-04', '0344-2338300', '2020-09-15', 3591, '15602-0280909-9', '', 'GHSS Chitor', '8th', '', 1),
(217217, 'Rahman Ali', 'Asim Gul', 'Male', '2009-02-02', '0342-0479525', '2020-09-15', 3593, '15602-9533411-3', '', 'GHSS Chitor', '8th', '', 1),
(217218, 'Mustafa Khan', 'Fazal Shah', 'Male', '2008-09-01', '0343-1922618', '2020-09-15', 3594, '15602-0248238-3', '', 'GHSS Chitor', '8th', '', 1),
(217219, 'Nasar Ali', 'Aqal Zada', 'Male', '2008-04-04', '0349-9458844', '2020-09-15', 3595, '15602-0508202-9', '', 'GHSS Chitor', '8th', '', 1),
(217220, 'LIaqat Ali', 'Wazir', 'Male', '2008-04-06', '0342-9704264', '2020-09-19', 3596, '15602-2559996-7', '', 'GHSS Chitor', '7th', '', 1),
(217221, 'Islam Ul Haq', 'Aziz Ul Haq', 'Male', '2008-12-14', '0346-1952693', '2020-09-28', 3603, '15602-0246934-7', '', 'GHSS Chitor', '8th', '', 1),
(217222, 'Muhammad Asghar Khan', 'Muhammad Kamal', 'Male', '2009-01-01', '0346-2990255', '2020-09-28', 3604, '15602-0255337-1', '', 'GHSS Chitor', '7th', '', 1),
(217223, 'Sabir Shah', 'Mian Syed Habib Shah', 'Male', '2008-03-07', '0349-8321235', '2020-10-02', 3610, '15602-4056361-3', '', 'GHSS Chitor', '8th', '', 1),
(217224, 'Hazrat Ali', 'Hazrat Rahman', 'Male', '2005-06-10', '0319-145311', '2020-10-20', 3615, '15602-0495989-3', '', 'GHSS Chitor', '8th', '', 1),
(217225, 'Muhammad Osama', 'Hussain Shah', 'Male', '2010-01-01', '0346-0991649', '2021-07-15', 3660, '15602-0245622-1', '', 'GHSS Chitor', '8th', '', 1),
(217226, 'Zakir Ullah', 'Said Aleem Shah', 'Male', '2007-04-01', '03', '2021-07-15', 3662, '', '', 'GHSS Chitor', '7th', '', 1),
(217227, 'Usman Ali', 'Sher Zameen', 'Male', '2008-09-25', '0347-9684296', '2021-08-02', 3670, '15602-0287419-1', '', 'GHSS Chitor', '7th', '', 1),
(217228, 'Muhammad Ismail', 'Muhammad Ishaq', 'Male', '2007-04-10', '0342-9638859', '2020-09-15', 3566, '15602-0244886-3', '', 'GHSS Chitor', '8th', '', 1),
(217229, 'Muhammad Maaz', 'Khan Bahadar', 'Male', '2008-04-10', '0348-0514088', '2020-09-15', 3567, '15602-1750127-3', '', 'GHSS Chitor', '8th', '', 1),
(217230, 'Fawad Khan', 'Sherin Zada', 'Male', '2008-01-12', '0347-4133488', '2020-09-15', 3568, '15602-391087-7', '', 'GHSS Chitor', '8th', '', 1),
(217231, 'Muhammad Bilal', 'Shahzad', 'Male', '2008-04-05', '0342-8144561', '2020-09-15', 3569, '15602-0336242-3', '', 'GHSS Chitor', '8th', '', 1),
(217232, 'Anwar Khan', 'Rahamdad Khan', 'Male', '2009-03-02', '0347-9531857', '2020-09-15', 3370, '15602-0336242-3', '', 'GHSS Chitor', '8th', '', 1),
(217233, 'Muhammad Ayaz', 'Khan Bahadar', 'Male', '2008-03-01', '0347-8957429', '2021-08-02', 3676, '15602-0245928-9', '', 'GHSS Chitor', '7th', '', 1),
(221021, 'Muhammad Ismail', 'Saad Muhammad', 'Male', '2004-12-06', '0333-4119207', '2022-09-02', 4173, '15602-1032381-7', '15602-', 'GHSS Chitor', '10th B', '', 1),
(221022, 'Muhmmad Abid', 'Sayed Yousaf Shah', 'Male', '1990-01-01', '03', '2022-09-03', 4270, '15602-', '15602-', 'GHSS Chitor', '10th B', '', 1),
(229210, 'Hanifullah', 'Khan Sadbar', 'Male', '2008-04-05', '0349-9355391', '2022-08-17', 4233, '15602-0291247-5', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229211, 'Shoukat Ali', 'Siraj-ud-din', 'Male', '2007-01-01', '0342-9169845', '2022-08-17', 4234, '15602-1651865-9', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229212, 'Rahimullah', 'Rozi Khan', 'Male', '2008-09-02', '0349-6101131', '2022-08-17', 4235, '15602-0452480-7', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229213, 'Muhammad Muddassir', 'Rozi Khan', 'Male', '2008-04-01', '0346-4765251', '2022-08-17', 4236, '15602-283511-7', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229214, 'Ismail Khan', 'Sher Afzal Khan', 'Male', '2007-02-01', '0348-2373577', '2022-08-17', 4237, '15602-4068527-5', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229215, 'Islam Khan', 'Afarin Khan', 'Male', '2007-03-20', '0343-5594770', '2022-08-17', 4238, '15602-4590018-9', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229216, 'Hazrat Ali', 'Taj Rahman', 'Male', '2007-04-16', '0346-8383195', '2022-08-17', 4240, '15602-4352400-3', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229217, 'Ali Sher', 'Alam Sher', 'Male', '2005-04-01', '0347-8908871', '2022-08-17', 4241, '15607-0676806-6', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229218, 'Salman Khan', 'Janat Gul', 'Male', '2007-01-01', '0344-6686070', '2022-08-17', 4242, '15602-0534948-1', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229219, 'Parvez Ali', 'Amir Rahman', 'Male', '2008-02-01', '0340-8970273', '2022-08-17', 4243, '15602-9003148-9', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229220, 'Habibullah', 'Azam Khan', 'Male', '2008-04-01', '0342-1911884', '2022-08-17', 4244, '15602-0247461-7', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229221, 'Bakht Alam', 'Khan Wazir', 'Male', '2007-01-05', '0345-5701032', '2022-08-17', 4245, '15602-4742518-3', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229222, 'Saeedullah Khan', 'Muhammad Zaman', 'Male', '2007-01-01', '0343-9133418', '2022-08-17', 4246, '15602-0247197-7', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229223, 'Shahid Khan', 'Khan Zada', 'Male', '2008-03-12', '0347-0458024', '2022-08-17', 4247, '15602-6631299-7', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229224, 'Umar Hayat', 'Said Rahman', 'Male', '1900-01-01', '0343-6050919', '2022-08-17', 4248, '15602-8696926-3', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229225, 'Muhammad Ghani', 'Wazir Zada', 'Male', '2008-04-15', '0342-3703096', '2022-08-17', 4249, '15602-0534954-7', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229226, 'Muhammad Ilyas', 'Amir Nawab', 'Male', '2008-01-01', '0347-9124388', '2022-08-17', 4250, '15602-8634487-3', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229227, 'Usman Ali', 'Shah Wali Khan', 'Male', '2006-01-01', '0341-0916012', '2022-08-17', 4251, '15602-8848672-9', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229228, 'Imad Ali', 'Said Rawan', 'Male', '2008-04-29', '03479124388', '2022-08-17', 4252, '15602-6769381-5', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229229, 'Muhammad Musa', 'Bakht Hussain', 'Male', '2008-01-01', '0346-9306829', '2022-08-17', 4253, '15602-8582506-5', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229230, 'Muhammad Ahmad', 'Shah Wali Khan', 'Male', '2007-03-20', '0346-9550621', '2022-08-17', 4254, '15602-7167608-3', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229231, 'Fazal Wahid', 'Karim', 'Male', '2007-01-01', '0346-9403197', '2022-08-17', 4255, '15101-1292078-0', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229232, 'Muhammad Sadiq', 'Shfrin Zada', 'Male', '2007-04-29', '0348-2441210', '2022-08-17', 4256, '15602-7023310-5', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229233, 'Farhan Ali', 'Fazal Ali', 'Male', '2007-08-11', '0340-2329813', '2022-08-17', 4258, '37405-2934088', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229234, 'Rafiullah', 'Bakht Sherawan', 'Male', '1900-01-01', '0345-1592084', '2022-08-17', 4259, '15602-', '15602-', 'GHSS Chitor', '9th B', '', 0),
(229235, 'Amanullah', 'Bacha Zada', 'Male', '2006-04-03', '0344-9892613', '2022-08-17', 4260, '15602-7691567-3', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229236, 'Junaid Khan', 'Javed Khan', 'Male', '1900-01-01', '0349-6693106', '2022-08-17', 4261, '15602-5339007-1', '15602-', 'GHSS Chitor', '9th B', '', 0),
(229237, 'Fazal Wadood', 'Akhtar Alam', 'Male', '2007-04-25', '0349-2177533', '2022-08-17', 4262, '15602-4565365-9', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229238, 'Samiullah', 'Khan Sadbar', 'Male', '2006-04-01', '0349-9355391', '2022-08-17', 4263, '15602-0291247-5', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229239, 'Salman Khan', 'Jan Muhammad', 'Male', '1900-01-01', '0344-1190107', '2022-08-17', 4264, '15602-3697072-9', '15602-', 'GHSS Chitor', '9th B', '', 0),
(229240, 'Abid Ahmad', 'Fazal Subhan', 'Male', '2008-03-25', '0315-9264409', '2022-09-20', 4272, '16101-1180490-1', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229241, 'Mehran Ali', 'Nazir Akbar', 'Male', '2007-05-02', '0348-9175889', '2022-09-24', 4271, '15602-51955975', '15602-', 'GHSS Chitor', '9th B', '', 0),
(229242, 'Roohullah', 'Peer Muhammad', 'Male', '2006-02-08', '03', '2022-11-07', 4273, '15602-', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229243, 'Umar Hayat', 'Said Rahman', 'Male', '2005-01-01', '03', '2022-11-11', 4277, '15602-', '15602-', 'GHSS Chitor', '9th B', '', 1),
(229244, 'Hazrat Hassan', 'Khan Bahadur', 'Male', '2006-11-06', '03', '2022-11-17', 4278, '15602-', '15602-', 'GHSS Chitor', '9th B', '', 1),
(2109101, 'Zeeshan Khan', 'Gul Zada', 'Male', '2006-05-01', '0334-9311856', '2021-07-01', 3350, '15602-1976010-3', '', 'GHSS Chitor', '10th A', '', 1),
(2109102, 'Hassan Khan', 'Sarzamin', 'Male', '2007-03-03', '0333-9471047', '2021-07-01', 3442, '15602-0532305-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109103, 'Irfan Ullah', 'Farid Jan', 'Male', '2005-01-05', '0341-4419807', '2021-07-01', 3449, '15602-5168017-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109104, 'Kamran Khan', 'Biladar', 'Male', '2004-04-10', '0340-9010535', '1900-01-01', 3454, '15602-7305946-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109105, 'Sanaullah', 'Muhammad Alam', 'Male', '2006-03-01', '0340-9250986', '1900-01-01', 3467, '15602-0417474-3', '', 'GHSS Chitor', '10th A', '', 1),
(2109106, 'Abbas Khan', 'Said Muhammad Khan', 'Male', '2007-04-15', '0346-9444197', '1900-01-01', 3473, '15602-0245809-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109107, 'Rokhan', 'Muhammad Ameen', 'Male', '2005-06-03', '0346-9421094', '1900-01-01', 3322, '15602-9459937-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109108, 'Najeeb Ullah', 'Dawlat Khan', 'Male', '2006-03-01', '0342-5924520', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109109, 'Jawad Ali', 'Naseeb Zada', 'Male', '2007-05-18', '0342-5271376', '1900-01-01', 3537, '15602-0254034-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109110, 'Maaz Khan', 'Sarzamin', 'Male', '2006-03-10', '0345-9009869', '1900-01-01', 3377, '15602-0250736-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109111, 'Israr Ali', 'Fazal Shah', 'Male', NULL, '0340-9310362', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 1),
(2109112, 'Shahid Ullah Bacha', 'Umar Badshah', 'Male', '2007-04-08', '0344-9673028', '1900-01-01', 3390, '15602-0247062-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109113, 'Hassan Khan', 'Hussain Shah', 'Male', '2007-01-01', '0340-0991049', '2007-01-01', 3484, '15602-0245622-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109114, 'Fayaz Khan', 'Ayaz', 'Male', '2006-05-25', '0347-1777214', '1900-01-01', 3420, '15602-5598604-5', '', 'GHSS Chitor', '10th A', '', 0),
(2109115, 'Samiullah', 'Umar Zada', 'Male', '2006-06-25', '0340-5854948', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109116, 'Shahid Khan', 'Sherin Buhar', 'Male', '2005-02-12', '0343-5882432', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109117, 'Rahmat Ali', 'Umar Gul', 'Male', '2006-05-10', '0323-9243734', '1900-01-01', 3429, '15602-0193352-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109118, 'Muhammad Ibrahim', 'Amir Rahim', 'Male', '2005-03-20', '0345-9307150', '1900-01-01', 3434, '15602-5879158-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109119, 'Said Rahman', 'Jehan Zeb', 'Male', '2006-05-02', '0341-9221083', '1900-01-01', 3436, '', '', 'GHSS Chitor', '10th A', '', 1),
(2109120, 'Mustafa Khan', 'Biladar', 'Male', '2006-11-12', '0342-1188024', '1900-01-01', 3465, '', '', 'GHSS Chitor', '10th A', '', 1),
(2109121, 'Jawad Ali', 'Dawa Khan', 'Male', '2006-04-01', '0345-9229834', '1900-01-01', 3535, '15602-0246917-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109122, 'Hazrat Bilal', 'Hamid Gul', 'Male', '2004-05-15', '0344-1982095', '1900-01-01', 3538, '15602-5757210-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109123, 'Anwar Said', 'Itbar Gul', 'Male', '2005-05-20', '03', '1900-01-01', 3612, '15602-4810412-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109124, 'Muhammad Ismail', 'Aziz Ur Rahman', 'Male', '2006-04-27', '0342-1935421', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109125, 'Najeebullah', 'Lal Gul', 'Male', '2005-04-15', '0348-9121364', '1900-01-01', 4069, '15602-0480365-3', '', 'GHSS Chitor', '10th A', '', 0),
(2109126, 'Anas Khan', 'Fazal Wahid', 'Male', '2006-03-01', '0346-8985521', '2006-03-01', 4071, '15602-1553576-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109127, 'Hamza Khan', 'Bakat Rahman', 'Male', '2007-04-10', '0348-9306052', '1900-01-01', 4073, '15602-2186430-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109128, 'Ibrahim Khan', 'Muhammad Said Khan', 'Male', '2007-03-15', '0342-9142718', '1900-01-01', 4075, '15602-2186430-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109129, 'Muhammad Maaz Khan', 'Shah Rasool Khan', 'Male', '2007-03-30', '0342-9667720', '1900-01-01', 4077, '15602-8804083-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109130, 'Muhammad Mustafa', 'Ali Rahman', 'Male', '2007-03-20', '0341-9490344', '1900-01-01', 4079, '15602-0244798-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109131, 'Samiullah', 'Bacha Khan', 'Male', '2006-01-01', '0344-8217515', '1900-01-01', 4081, '15602-4008303-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109132, 'Umar Rahman', 'Bakht Rahman', 'Male', '2006-01-01', '0349-5608239', '1900-01-01', 4083, '15602-7777527-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109133, 'Shafiullah', 'Shaikh', 'Male', '2006-01-01', '0344-8217515', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109134, 'Habib Ullah', 'Jehan Zar', 'Male', '2002-08-01', '0346-9994132', '1900-01-01', 4091, '15602-4644585-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109135, 'Asmat Ullah', 'Hazir Gul', 'Male', NULL, '0346-9341275', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109136, 'Muhammad Kamran', 'Amin Khan', 'Male', '2005-04-10', '0346-9994123', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109137, 'Rafiq Hassan', 'Nasar Ali', 'Male', '2006-04-10', '0340-9012206', '1900-01-01', 4099, '15602-8899200-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109138, 'Murtaza Khan', 'Khaista Rahman', 'Male', '2006-02-01', '0346-3009330', '1900-01-01', 4101, '15602-5955546-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109139, 'Alam Zeb', 'Said Rahman', 'Male', '2006-02-01', '0343-6058919', '1900-01-01', 4103, '', '', 'GHSS Chitor', '10th A', '', 0),
(2109140, 'Rahman Ullah', 'Azim Khan', 'Male', '2007-01-02', '03', '1900-01-01', 4105, '15602-5955546-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109141, 'Aftab Alam', 'Fazal Subhan', 'Male', '2007-01-01', '03', '1900-01-01', 4107, '1560-0247695-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109142, 'Waheedullah', 'Rahamdad Khan', 'Male', '2007-03-25', '03', '1900-01-01', 4109, '15602-0361352-3', '', 'GHSS Chitor', '10th A', '', 1),
(2109143, 'Muhammad Islam', 'Sargand', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109144, 'Tahir Khan', 'Bakht Zada', 'Male', '2006-03-15', '03', '1900-01-01', 4113, '15602-0362919-3', '', 'GHSS Chitor', '10th A', '', 1),
(2109145, 'Rahmat Ullah', 'Alam Zeb', 'Male', '2006-02-04', '0341-5684624', '1900-01-01', 4115, '15602-0130906-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109146, 'Midrarullah', 'Rahmat Ali', 'Male', '2005-04-01', '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109147, 'Rooh Ullah', 'Pir Muhammad', 'Male', '2006-02-08', '0343-9590272', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109148, 'Anwar Shah', 'Muhammad Alam', 'Male', '2006-02-02', '0344-5961509', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109149, 'Hasnain Khan', 'Niaz Muhammad', 'Male', '2005-01-10', '0340-2670455', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109150, 'Jawad Ali', 'Habib Khan', 'Male', '2005-02-15', '0344-9728164', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109151, 'Irfan Ullah', 'Muhammad Ali', 'Male', '2007-04-10', '0340-2110916', '1900-01-01', 4126, '15602-0279437-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109152, 'Umar Raziq', 'Fazal Rahman', 'Male', '2004-03-15', '0346-8273822', NULL, 4274, NULL, NULL, 'GHSS Chitor', '9th B', '', 1),
(2109153, 'Muhammad Zeeshan', 'Amir Zeb', 'Male', '2007-01-10', '0341-0910384', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109154, 'Attaullah', 'Mujahid', 'Male', '2007-01-05', '0345-9459609', '1900-01-01', 4135, '15602-0265019-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109155, 'Kashif Khan', 'Ahmad Zeb', 'Male', '2004-02-12', '0348-5351147', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109156, 'Muhammad Hussain', 'Shah Faisal', 'Male', '2005-02-11', '0340-2670358', NULL, NULL, '', NULL, 'GHSS Chitor', '10th A', '', 0),
(2109157, 'Adnan Khan', 'Umar Sherin', 'Male', '2007-04-07', '0342-2557768', '1900-01-01', 4141, '', '', 'GHSS Chitor', '10th A', '', 1),
(2109158, 'Asadullah Khan', 'Said Muhammad', 'Male', '2004-04-08', '0345-9452714', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109159, 'Muhammad Hazrat Bilal', 'Fazal Subhan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109160, 'Irfan Ullah', 'Azim Khan', 'Male', '2005-03-01', '0344-9124714', '1900-01-01', 4147, '15602-5955546-1', '', 'GHSS Chitor', '10th A', '', 1),
(2109161, 'Muhammad Uzaib', 'Bakht Zaman', 'Male', '2007-01-01', '0343-2569460', '1900-01-01', 4149, '15602-1387226-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109162, 'Alam Khan', 'Khalid', 'Male', '2001-05-25', '0340-9554369', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109163, 'Muhammad Yaseen', 'Mian Khaliq Jan', 'Male', '2007-01-15', '0342-6328567', '1900-01-01', 4155, '15602-0249233-9', '', 'GHSS Chitor', '10th A', '', 1),
(2109164, 'Salman Khan', 'Taleimand', 'Male', '2005-01-08', '0340-7425566', '1900-01-01', 4157, '15602-3949115-9', '', 'GHSS Chitor', '10th A', '', 0),
(2109165, 'Rahimullah', 'Gul Nausher', 'Male', '2005-02-01', '0340-9011902', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109166, 'Zahid Hussain', 'Fida Hussain', 'Male', '2007-01-01', '0347-1098297', '1900-01-01', 4158, '15602-8485327-5', '', 'GHSS Chitor', '10th A', '', 1),
(2109167, 'Ikram Khan', 'Sher Afzal Khan', 'Male', '2003-05-10', '0341-0252003', '1900-01-01', 4161, '15602-0508100-3', '', 'GHSS Chitor', '10th A', '', 1),
(2109168, 'Mushtaq Haidar', 'Shah Bahadar', 'Male', '2003-03-03', '0340-2869217', '1900-01-01', 3481, '15602-7239666-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109169, 'Rahmat Ali', 'Akhtar Ali', 'Male', '2005-01-12', '0344-3551391', '1900-01-01', 4153, '15602-2078221-3', '', 'GHSS Chitor', '10th A', '', 0),
(2109170, 'Khalid Zada', 'Khaperai', 'Male', '2007-04-04', '0346-4632400', '1900-01-01', 4165, '15602-8528072-7', '', 'GHSS Chitor', '10th A', '', 1),
(2109171, 'Muhammad Ibrahim', 'Muhammad Amal', 'Male', '2007-04-02', '0348-4209249', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109172, 'Hayat Khan', 'Muhabbat Khan', 'Male', '2004-01-01', '0348-9466799', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109173, 'Fazal Rashid ', 'Bakhtyar', 'Male', NULL, '0344-2874944', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th A', '', 0),
(2109201, 'Muhammad Yaseen', 'Khan Bahadur', 'Male', '2004-04-07', '0347-8957429', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109202, 'Inamullah', 'Amir Afzal', 'Male', '2005-01-01', '0341-8358398', '1900-01-01', 4043, '15602-0257385-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109203, 'Mubeen Mian', 'Umar Jehan', 'Male', '2006-04-10', '0348-8975560', '1900-01-01', 4044, '', '', 'GHSS Chitor', '10th B', '', 1),
(2109204, 'Mian Said Khalil Ullah', 'Karim Dad', 'Male', '2007-04-05', '0321-9768048', '1900-01-01', 4045, '15601-6048509-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109205, 'Rahmat Ali', 'Ezat Muhammad', 'Male', '2004-04-10', '0342-8978561', '1900-01-01', 4046, '15602-0250620-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109206, 'Zahidullah', 'Muhammad Nawab', 'Male', '2007-03-20', '0346-9444184', '1900-01-01', 4047, '15602-0534859-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109207, 'Muhammad Suliman', 'Umar Rashid', 'Male', '2006-02-26', '0346-3879998', '1900-01-01', 4048, '15101-5896784-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109208, 'Abdur Rahman', 'Habib Ur Rahman', 'Male', '2005-04-04', '0340-9276791', '1900-01-01', 4049, '15602-0407958-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109209, 'Abdullah', 'Bakht Rawan', 'Male', '2005-04-05', '0348-8068958', '1900-01-01', 4066, '15602-9902150-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109210, 'Zia Hussain', 'Alamgir', 'Male', '2005-05-07', '0342-9567482', '1900-01-01', 4051, '15602-0246993-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109211, 'Shafiullah', 'Khan Zarin', 'Male', '2007-06-01', '0346-8910601', '1900-01-01', 4052, '15602-0245615-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109212, 'Faisal Khan', 'Umar Muhammad', 'Male', '2006-03-11', '0305-9618026', '1900-01-01', 4053, '15602-0254967-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109213, 'Muhammad Abdullah', 'Bakht Zada', 'Male', '2006-06-22', '0347-8803996', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109214, 'Shah Fahad', 'Rahimullah', 'Male', '2003-11-11', '0348-5319968', '1900-01-01', 4055, '15602-0496254-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109215, 'Sultan Zarin', 'Gul Zarin', 'Male', '2003-06-10', '0348-1959293', '1900-01-01', 4056, '15602-0262064-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109216, 'Sajawat Khan', 'Muhammad Zada', 'Male', NULL, '0348-3064423', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109217, 'Abdur Rahman', 'Shah Wazir Khan', 'Male', '2005-03-10', '0340-9735645', '1900-01-01', 4057, '15602-0461743-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109218, 'Abdullah', 'Ayub Khan', 'Male', '2005-04-20', '0340-9552216', '1900-01-01', 4058, '15602-0245776-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109219, 'Ihtisham ul Haq', 'Wali Rahman', 'Male', '2006-03-25', '0348-7427862', '1900-01-01', 4059, '15602-6314627-3', '', 'GHSS Chitor', '10th B', '', 1),
(2109220, 'Muhammad Mustafa', 'Rahim Dad', 'Male', '2005-01-24', '0347-6254928', '1900-01-01', 4060, '', '', 'GHSS Chitor', '10th B', '', 1),
(2109221, 'Mohsin Haider', 'Rahman Haider', 'Male', '2007-01-10', '0347-0192470', '1900-01-01', 4061, '15602-0262034-1', '', 'GHSS CHITOR', '10th B', '', 1),
(2109222, 'Husan Wahab', 'Fazal Hadi', 'Male', '2007-11-03', '0342-0911700', '1900-01-01', 4062, '15602-0254029-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109223, 'Najeeb Ullah', 'Raza Khan', 'Male', '2006-03-01', '0340-6795749', '1900-01-01', 4063, '15602-3783096-3', '', 'GHSS Chitor', '10th B', '', 1),
(2109224, 'Riaz Ahmad', 'Bakht Sharif', 'Male', '2004-04-01', '0348-9034861', '1900-01-01', 4064, '15602-0265080-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109225, 'Sanaullah', 'Amir Nowshad', 'Male', '2004-04-01', '0348-0514052', '1900-01-01', 4065, '15602-3454774-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109226, 'Muhammad Mubeen', 'Fida Ali Khan', 'Male', '2006-04-05', '0348-9121170', '1900-01-01', 4072, '15602-6482513-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109227, 'Sadiq Zada', 'Nawab Zada', 'Male', NULL, '0344-8053315', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109228, 'Fazal Khan', 'Payo Khan', 'Male', '2007-03-15', '0345-0598271', '1900-01-01', 4076, '15602-3078007-3', '', 'GHSS Chitor', '10th B', '', 1),
(2109229, 'Muhammad Faizan', 'Aftab Hussain', 'Male', '2007-03-30', '0346-8004818', '1900-01-01', 4078, '15602-4063778-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109230, 'Shafiq Khan', 'Ziarat Gul', 'Male', '2004-02-02', '0347-5663938', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109231, 'Hamidur Rahman', 'Taj Amin Khan', 'Male', '2006-01-01', '0344-2543224', '1900-01-01', 4082, '15602-8906586-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109232, 'Usman Ali', 'Khan Badshah', 'Male', '2006-05-04', '0340-5853992', '1900-01-01', 4084, '15602-6940214-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109233, 'Anwar Khan', 'Gul Khan', 'Male', '2005-01-01', '0344-8187217', '1900-01-01', 4086, '15602-784969-3', '', 'GHSS Chitor', '10th B', '', 1),
(2109234, 'Farooq Hassan', 'Zafar Ali', 'Male', '2006-03-30', '0340-9012306', '1900-01-01', 4088, '15602-4830457-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109235, 'Ziaullah Khan', 'Raid Ali Khan', 'Male', '2006-04-10', '0342-3068243', '1900-01-01', 4090, '15602-0504395-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109236, 'Imran Khan', 'Amir Afzal', 'Male', '2005-04-01', '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109237, 'Amir Alam Khan', 'Alam Sher', 'Male', '2006-01-01', '0344-3560199', '1900-01-01', 4094, '15602-4327042-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109238, 'Abdullah', 'Habib Gul', 'Male', NULL, '0340-6506653', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109239, 'Faisal Khan', 'Muhammad Khan', 'Male', NULL, '0345-0947463', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109240, 'Misal Khan', 'Sherin Zada', 'Male', '2005-01-01', '0344-2884707', '1900-01-01', 4100, '', '', 'GHSS Chitor', '10th B', '', 1),
(2109241, 'Najeeb Ullah', 'Qasim Jan', 'Male', '2005-04-01', '0344-3284908', '1900-01-01', 4102, '1562-3783696-3', '', 'GHSS Chitor', '10th B', '', 1),
(2109242, 'Abu Bakar Sadiq', 'Sher Baz Khan', 'Male', '2007-01-01', '0347-9437868', '1900-01-01', 4104, '15602-6454653-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109243, 'Afzal Inam', 'Bakht Afsar', 'Male', '2007-01-03', '0344-2648087', '1900-01-01', 4106, '1562-0787949-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109244, 'Inam Ullah', 'Bakht Zada', 'Male', '2007-01-01', '0344-9606272', '1900-01-01', 4108, '15602-0285286-3', '', 'GHSS Chitor', '10th B', '', 1),
(2109245, 'Inamullah', 'Sher Muhammad', 'Male', '2007-03-15', '0345-9515023', '1900-01-01', 4110, '', '', 'GHSS Chitor', '10th B', '', 1),
(2109246, 'Abdullah', 'Qayoom Khan', 'Male', '1900-01-01', '03', '1900-01-01', 999999, '', '', 'GHSS Chitor', '10th B', '', 1),
(2109247, 'Yar Hussain', 'Sher Zada', 'Male', '1900-01-01', '0341-3787629', '1900-01-01', 4114, '15602-5505446-9', '', 'GHSS Chitor', '10th B', '', 0),
(2109248, 'Abu Bakar Sadiq', 'Alam Gul', 'Male', '2006-04-10', '0341-3787629', '1900-01-01', 4116, '15602-0926159-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109249, 'Umar Hayat', 'Umar Wahid', 'Male', '2006-01-09', '0341-8943348', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109250, 'Ikramullah', 'Aqal Zada', 'Male', '2005-03-15', '0345-4369153', '2011-07-12', 4120, '', '', 'GHSS Chitor', '10th B', '', 1),
(2109251, 'Ubaid Ullah', 'Hakim Khan', 'Male', '2005-02-15', '0340-9486231', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109252, 'Muhammad Sohail', 'Khurshid', 'Male', '2006-04-07', '0321-9065266', '1900-01-01', 4124, '15602-0246321-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109253, 'Gawhar Khan', 'Abdur Rauf', 'Male', '2005-02-02', '0340-9486315', '1900-01-01', 4127, '15602-0280222-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109254, 'Muhammad Noman', 'Bakht Amin', 'Male', '2004-04-10', '0342-9835740', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109255, 'Muhammad Adnan', 'Yousaf Khan', 'Male', '2005-03-20', '0343-4854872', '1900-01-01', 4130, '', '', 'GHSS Chitor', '10th B', '', 1),
(2109256, 'Muhammad Muzamil ', 'Shamsher Ali', 'Male', '2006-01-01', '0334-8993405', '1900-01-01', 4134, '', '', 'GHSS Chitor', '10th B', '', 0),
(2109257, 'Aleem ullah', 'Ismail', 'Male', NULL, '0344-3777293', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109258, 'Zeeshan Ali', 'Akhtar Ali', 'Male', '2005-07-01', '0344-9665765', '1900-01-01', 4138, '15602-5635301-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109259, 'Umar Rahim', 'Gul Rahsd', 'Male', '2005-02-10', '0393522398', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109260, 'Yasir Ullah', 'Mani Rahim', 'Male', '2005-03-12', '0344-9823860', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109261, 'Razaullah', 'Hazrat Sher', 'Male', '2008-02-03', '0302-2486736', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109262, 'Hamid Ullah', 'Umar Zeb', 'Male', NULL, '0346-6490612', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109263, 'Muhammad Waqas', 'Dawood Khan', 'Male', NULL, '0345-0817371', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109264, 'Nisar Ali', 'Alam Khan', 'Male', '2007-01-01', '0348-9120977', '1900-01-01', 4150, '15602-0285154-7', '', 'GHSS Chitor', '10th B', '', 1),
(2109265, 'Akbar Ali', 'Anwar Ali', 'Male', '2005-01-01', '0345-9191811', '1900-01-01', 4152, '15602-6370301-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109266, 'Sar Said', 'Farooq', 'Male', NULL, '0349-3522390', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109267, 'Qasim Ullah', 'Samiullah', 'Male', NULL, '0340-8866002', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109268, 'Muhammad Mobeen', 'Nadar Khan', 'Male', '2007-01-11', '0340-9885009', '1900-01-01', 4159, '15602-0253098-1', '', 'GHSS Chitor', '10th B', '', 1),
(2109269, 'Hazrat Ullah', 'Akhtar Ali', 'Male', '2007-01-04', '0345-9514905', '1900-01-01', 4164, '15602-0392905-9', '', 'GHSS Chitor', '10th B', '', 1),
(2109270, 'Anwar Ali', 'Qadar Gul', 'Male', NULL, '0345-3209305', NULL, NULL, NULL, NULL, 'GHSS Chitor', '10th B', '', 0),
(2109271, 'Jehan Zeb Khan', 'Bahroz Khan', 'Male', '2005-01-01', '0348-4645377', '1900-01-01', 4169, '15602-0534945-3', '', 'GHSS Chitor', '10th B', '', 1),
(2109272, 'AmIn Ullah', 'Said Jalal', 'Male', '2007-01-01', '0340-2670265', '1900-01-01', 4170, '15602-0513839-5', '', 'GHSS Chitor', '10th B', '', 1),
(2109273, 'Bakht AmIn', 'Ali Haidar', 'Male', '2007-01-01', '0341-4245441', '1900-01-01', 4172, '15602-1049319-1', '', 'GHSS Chitor', '10th B', '', 1),
(2110102, 'Habib Ullah', ' Azim Khan\r\n', 'Male', NULL, '0348-9409419', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110103, 'Abid Ali', ' Ali Khan', 'Male', NULL, '0342-9664718', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110104, 'Muhammad Khan', 'Sher Muhammad Khan', 'Male', NULL, '0345-9378028', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110105, 'Ahmad Khan', 'Muhammad Rashad', 'Male', NULL, '0342-9607049', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110106, 'Ihsan Ullah', ' Umar Zaman', 'Male', NULL, '0340-3299249', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110107, 'Qaisar Khan', 'Amir Hamza', 'Male', NULL, '0347-1739026', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110108, 'Shoaib Khan', 'Gul Khan', 'Male', NULL, '0342-0981443', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110109, 'Ihsan Ullah', ' Khan Gul', 'Male', NULL, '0343-0279785', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110110, 'Hassan Khan', ' Asaf Khan \r\n', 'Male', NULL, '0343-4025849', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110111, 'Rahim Khan', ' Amir Dost Khan\r\n', 'Male', NULL, '0313-0972390', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110112, 'Ihsan Ali Khan', ' Amir Nawab', 'Male', NULL, '0347-9124388', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110113, 'Shehzad Khan', ' Said Rahim\r\n', 'Male', NULL, '0340-5908866', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110114, 'Ijaz Ahmad', ' Farid Khan\r\n', 'Male', NULL, '0346-9550826', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110115, 'Rahim Ullah', ' Taj Muhammad Khan\r\n', 'Male', NULL, '0342-1188794', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110116, 'Muhammad Ilyas', ' Rahmat Ali\r\n', 'Male', NULL, '0341-2054439', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110117, 'Latif Shah ', ' Imtiaz Khan\r\n', 'Male', NULL, '0348-7435422', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110118, 'Muhammad Zeb', ' Sherin Zada\r\n', 'Male', NULL, '0343-9306915', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110119, 'Muhammad Waqas', ' Aslam Khan\r\n', 'Male', NULL, '0341-9090491', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110120, 'Muhammad Hussain', ' Fazal Qayum\r\n', 'Male', NULL, '0347-2615746', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110121, 'Ikram Ullah', ' Zafar Ali\r\n', 'Male', NULL, '0342-9648968', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110122, 'Ihsan Ullah', ' Bahram Khan', 'Male', NULL, '0349-7304235', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110123, 'Attaullah Shah', ' Jamil Muhammad Khan\r\n', 'Male', NULL, '0348-5353293', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110124, 'Abdullah', ' Sherzada\r\n', 'Male', NULL, '0348-9360766', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110125, 'Rahid Khan', ' Bakht Farid Khan', 'Male', NULL, '0344-5187324', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110126, 'Muhammad Idress', ' Abdur Rahman\r\n', 'Male', NULL, '0347-6731604', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110127, 'Kashif Ahmad', ' Fazal Maula\r\n', 'Male', NULL, '0346-5435796', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110128, 'Muhammad Anees', 'Muhammad Younas', 'Male', NULL, '0344-9662527', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110129, 'Muhammad Rawan', 'Aqal Mand', 'Male', NULL, '0341-1462194', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110130, 'Nisar Ali', ' Asil Zada\r\n', 'Male', NULL, '0344-9609337', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110131, 'Abu Bakar', ' Amir Rahman\r\n', 'Male', NULL, '0312-9284566', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110132, 'Asad Ali', ' Mian Said Ghani\r\n', 'Male', NULL, '0343-9069479', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110133, 'Ainan Hussain', ' Muhammad Ali Shah\r\n', 'Male', NULL, '0340-9477954', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110134, 'Syed Mansoor Shah', ' Sayed Wali Shah\r\n', 'Male', NULL, '0341-5357914', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110135, 'Zahir Khan', ' Ayub Khan\r\n', 'Male', NULL, '0342-9605966', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110136, 'Seyab Hussain', ' Jehangir Mian\r\n', 'Male', NULL, '0345-983645', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110137, 'Hamza Bacha', ' Fazal Badshah\r\n', 'Male', NULL, '0344-8961663', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110138, 'Hamza Khan', ' Bahadar Khan', 'Male', NULL, '0346-8866073', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110139, 'Azmat Ali', ' Sher Rahman\r\n', 'Male', NULL, '0346-7428814', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110140, 'Tahir Zada', ' Mohin zada\r\n', 'Male', NULL, '0340-9890773', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110141, 'Ubaid Ullah', ' Bakhti gul\r\n', 'Male', NULL, '0342-5398811', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110142, 'Dawood Khan', ' Shahi Rahman\r\n', 'Male', NULL, '0348-9612340', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110143, 'Muhib Ul Haq', ' Aziz Ul Haq', 'Male', NULL, '0346-1952693', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110144, 'Fazal Mahboob', ' Fazal Rahman', 'Male', NULL, '0341-8040588', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110145, 'Muhammad Usama', ' Shah Faisal\r\n', 'Male', NULL, '0349-9458798', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110201, 'Muslim Khan', 'Sher Zaman', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110202, 'Sabair Shah', 'Momin', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110203, 'Ikram Khan', 'Fazal Raziq', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110204, 'Ihsan Ullah', 'Gul Ali', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110205, 'Muhammad Kaleem', 'Muhammad Salim', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110206, 'Sheraz Khan', 'Mishal Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110207, 'Afsar Ali', 'Akbar Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110208, 'Saeed Ullah', 'Raham dad Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110209, 'Muhammad Salim', 'Muhammad Karim', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110210, 'Inamullah', 'Muhammad Ali Shah', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110211, 'Umar Rahman', 'Fazal Rahman', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110212, 'Niaz Alam', 'Muhammad Iqbal', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110213, 'Rahim Ullah', 'Umar Qayum', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110214, 'Abu Bakar Khan', 'Wazir Zada', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110215, 'Muhammad Yaseen', 'Amir Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110216, 'Salman Khan', 'Shahzad', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110217, 'Muhammad Abbas', 'Fazal Rabi', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110218, 'Muhammad Sadiq', 'Khan Zada', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110219, 'Muhammad Ismail', 'Anwar Zaman', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110220, 'Salman Ali', 'Afzal Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110221, 'Muhammad Abu Bakar', 'Fazal Rahman', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110222, 'Syed Mian Bacha', 'Mian Karim Dad', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110223, 'Najeeb Ullah', 'Muhammad Zada', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110224, 'Abdullah', 'Naimat Gul', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110225, 'Luqman Khan', 'Taj Muhammad Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110226, 'Ubaid Ullah', 'Umar Rahman', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110227, 'Ihsan Ullah', 'Akbar Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110228, 'Mudasir Khan', 'Bahadar Sher Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110229, 'Haseen Zada', 'Khan Zada', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110230, 'Usman Ali', 'Itbar Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110231, 'Rohil Amin', 'Muhammad Akbar', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110232, 'Maaz Ahmad', 'Jehan Mulk', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110233, 'Tahir Khan', 'Javid', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110234, 'Mohsin Badsha', 'Muhammad Rahman', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110235, 'Syed Noor Ahmad Shah', 'Syed Wali Shah', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110236, 'Muhammad Anees Khan', 'Aqal Zeb', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110237, 'Hamza Khan', 'Palash Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110238, 'Muhammad Ishaq Bacha', 'Sabj Ali Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110239, 'Razaq Haider', 'Amir Haider', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110240, 'Yasir Ullah', 'Sultan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110241, 'Wali Khan', 'Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110242, 'Niaz Muhammad', 'Yousaf Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110243, 'Azizullah', 'Wazir', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110244, 'Abdullah', 'Fazal Akbar', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1);
INSERT INTO `students_info` (`Roll_No`, `Name`, `FName`, `Gender`, `Dob`, `Mobile_No`, `Admission_Date`, `Admission_No`, `Father_Cnic`, `Student_Form_B`, `School`, `Class`, `Class_Position`, `Status`) VALUES
(2110245, 'Roman Ali', 'Muhammad Bacha', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110246, 'Aqal Khan', 'Afzal Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110247, 'Muhammad Abrar', 'Muzafar Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110248, 'Kamil Khan', 'Alam Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110249, 'Azaz Hussain', 'Bakht Hussain', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110250, 'Asad Ullah', 'Sherin Buhar', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110251, 'Razi Khan', 'Dost Muhammad Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1),
(2110252, 'Sajjad Ali', 'Amin Khan', 'Male', NULL, '03', NULL, NULL, NULL, NULL, 'GHSS Chitor', '11th', '', 1);

-- --------------------------------------------------------

--
-- Table structure for table `subjects`
--

CREATE TABLE `subjects` (
  `Id` int(11) NOT NULL,
  `Name` varchar(30) NOT NULL,
  `Status` tinyint(4) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `subjects`
--

INSERT INTO `subjects` (`Id`, `Name`, `Status`) VALUES
(1, 'English', 1),
(2, 'Urdu', 1),
(3, 'Maths', 1),
(4, 'Computer Science', 1),
(5, 'Islamyat', 1),
(6, 'History And Geography', 1),
(7, 'Hpe', 1),
(8, 'General Science', 1),
(9, 'Qirat', 1),
(10, 'Arabic', 1),
(11, 'Drawing', 1),
(12, 'Mutalia Quran', 1),
(13, 'Pashto', 1),
(14, 'Nazira', 1),
(15, 'Physics', 1),
(16, 'Social Study', 1),
(17, 'Chemistry', 1),
(18, 'Biology', 1),
(19, 'Pak Study', 1),
(22, 'Introduction to Computing', 1),
(23, 'Financial Accounting Managemen', 1),
(24, 'C plus plus 3', 1);

-- --------------------------------------------------------

--
-- Table structure for table `subject_teacher`
--

CREATE TABLE `subject_teacher` (
  `Id` int(11) NOT NULL,
  `Class_Subject_Id` int(11) NOT NULL,
  `Teacher_Id` int(11) NOT NULL,
  `Status` int(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `subject_teacher`
--

INSERT INTO `subject_teacher` (`Id`, `Class_Subject_Id`, `Teacher_Id`, `Status`) VALUES
(1, 1, 1, 1),
(2, 2, 2, 1),
(3, 3, 2, 1),
(4, 4, 1, 1),
(5, 5, 1, 1),
(6, 6, 1, 1),
(7, 7, 2, 1);

-- --------------------------------------------------------

--
-- Table structure for table `tab_index`
--

CREATE TABLE `tab_index` (
  `Tab_index_id` int(11) NOT NULL,
  `English` int(11) NOT NULL,
  `Urdu` int(11) NOT NULL,
  `Maths` int(11) NOT NULL,
  `Hpe` int(11) NOT NULL,
  `Nazira` int(11) NOT NULL,
  `Science` int(11) NOT NULL,
  `Arabic` int(11) NOT NULL,
  `Islamyat` int(11) NOT NULL,
  `History` int(11) NOT NULL,
  `Computer` int(11) NOT NULL,
  `Mutalia` int(11) NOT NULL,
  `Qirat` int(11) NOT NULL,
  `Drawing` int(11) NOT NULL,
  `Social` int(2) NOT NULL DEFAULT 0,
  `Pashto` int(2) NOT NULL DEFAULT 0,
  `Biology` int(2) NOT NULL,
  `Chemistry` int(2) NOT NULL,
  `Physics` int(2) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `tab_index`
--

INSERT INTO `tab_index` (`Tab_index_id`, `English`, `Urdu`, `Maths`, `Hpe`, `Nazira`, `Science`, `Arabic`, `Islamyat`, `History`, `Computer`, `Mutalia`, `Qirat`, `Drawing`, `Social`, `Pashto`, `Biology`, `Chemistry`, `Physics`) VALUES
(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 3, 12, 13, 14, 15, 16, 17, 18, 19);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `class_subjects`
--
ALTER TABLE `class_subjects`
  ADD PRIMARY KEY (`Id`),
  ADD UNIQUE KEY `uqSchool_Class_Subject` (`School_Id`,`Class_Id`,`Subject_Id`),
  ADD KEY `class_id_reference` (`Class_Id`),
  ADD KEY `subject_id_reference` (`Subject_Id`);

--
-- Indexes for table `employees`
--
ALTER TABLE `employees`
  ADD PRIMARY KEY (`Id`);

--
-- Indexes for table `login`
--
ALTER TABLE `login`
  ADD PRIMARY KEY (`Id`),
  ADD UNIQUE KEY `username` (`User_Name`),
  ADD KEY `Employee_Id` (`Employee_Id`);

--
-- Indexes for table `marks`
--
ALTER TABLE `marks`
  ADD PRIMARY KEY (`Serial_No`),
  ADD UNIQUE KEY `forign` (`Roll_No`);

--
-- Indexes for table `position`
--
ALTER TABLE `position`
  ADD PRIMARY KEY (`Serial_No`),
  ADD UNIQUE KEY `po` (`Roll_No`);

--
-- Indexes for table `schools`
--
ALTER TABLE `schools`
  ADD PRIMARY KEY (`Id`),
  ADD UNIQUE KEY `Name` (`Name`);

--
-- Indexes for table `school_classes`
--
ALTER TABLE `school_classes`
  ADD PRIMARY KEY (`Id`),
  ADD UNIQUE KEY `unique_index` (`Name`,`School_Id`),
  ADD KEY `school_id` (`School_Id`);

--
-- Indexes for table `setting`
--
ALTER TABLE `setting`
  ADD PRIMARY KEY (`User_Id`),
  ADD KEY `selected_school` (`Selected_School_Id`),
  ADD KEY `selected_class` (`Selected_Class_Id`);

--
-- Indexes for table `students_info`
--
ALTER TABLE `students_info`
  ADD PRIMARY KEY (`Roll_No`),
  ADD UNIQUE KEY `uniqe_adm` (`Admission_No`);

--
-- Indexes for table `subjects`
--
ALTER TABLE `subjects`
  ADD PRIMARY KEY (`Id`),
  ADD UNIQUE KEY `Name` (`Name`);

--
-- Indexes for table `subject_teacher`
--
ALTER TABLE `subject_teacher`
  ADD PRIMARY KEY (`Id`),
  ADD KEY `class_subject` (`Class_Subject_Id`),
  ADD KEY `subject_teacher` (`Teacher_Id`);

--
-- Indexes for table `tab_index`
--
ALTER TABLE `tab_index`
  ADD PRIMARY KEY (`Tab_index_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `class_subjects`
--
ALTER TABLE `class_subjects`
  MODIFY `Id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `employees`
--
ALTER TABLE `employees`
  MODIFY `Id` int(2) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `login`
--
ALTER TABLE `login`
  MODIFY `Id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `marks`
--
ALTER TABLE `marks`
  MODIFY `Serial_No` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `position`
--
ALTER TABLE `position`
  MODIFY `Serial_No` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1512;

--
-- AUTO_INCREMENT for table `schools`
--
ALTER TABLE `schools`
  MODIFY `Id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `school_classes`
--
ALTER TABLE `school_classes`
  MODIFY `Id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=26;

--
-- AUTO_INCREMENT for table `subjects`
--
ALTER TABLE `subjects`
  MODIFY `Id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

--
-- AUTO_INCREMENT for table `subject_teacher`
--
ALTER TABLE `subject_teacher`
  MODIFY `Id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `tab_index`
--
ALTER TABLE `tab_index`
  MODIFY `Tab_index_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `class_subjects`
--
ALTER TABLE `class_subjects`
  ADD CONSTRAINT `class_id` FOREIGN KEY (`Class_Id`) REFERENCES `school_classes` (`Id`),
  ADD CONSTRAINT `class_subjects_ibfk_1` FOREIGN KEY (`School_Id`) REFERENCES `schools` (`Id`),
  ADD CONSTRAINT `subject_id` FOREIGN KEY (`Subject_Id`) REFERENCES `subjects` (`Id`);

--
-- Constraints for table `login`
--
ALTER TABLE `login`
  ADD CONSTRAINT `emp_id` FOREIGN KEY (`Employee_Id`) REFERENCES `employees` (`Id`);

--
-- Constraints for table `marks`
--
ALTER TABLE `marks`
  ADD CONSTRAINT `forkey` FOREIGN KEY (`Roll_No`) REFERENCES `students_info` (`Roll_No`);

--
-- Constraints for table `school_classes`
--
ALTER TABLE `school_classes`
  ADD CONSTRAINT `school_id` FOREIGN KEY (`School_Id`) REFERENCES `schools` (`Id`);

--
-- Constraints for table `setting`
--
ALTER TABLE `setting`
  ADD CONSTRAINT `selected_class` FOREIGN KEY (`Selected_Class_Id`) REFERENCES `school_classes` (`Id`),
  ADD CONSTRAINT `selected_school` FOREIGN KEY (`Selected_School_Id`) REFERENCES `schools` (`Id`),
  ADD CONSTRAINT `user_id` FOREIGN KEY (`User_Id`) REFERENCES `employees` (`Id`);

--
-- Constraints for table `subject_teacher`
--
ALTER TABLE `subject_teacher`
  ADD CONSTRAINT `class_subject_fk` FOREIGN KEY (`Class_Subject_Id`) REFERENCES `class_subjects` (`Id`),
  ADD CONSTRAINT `teacher_id` FOREIGN KEY (`Teacher_Id`) REFERENCES `employees` (`Id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
