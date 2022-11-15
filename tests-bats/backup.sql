-- MySQL dump 10.13  Distrib 8.0.29, for Linux (x86_64)
--
-- Host: localhost    Database: datadonation
-- ------------------------------------------------------
-- Server version	8.0.29

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `DataDonationEntries`
--

DROP TABLE IF EXISTS `DataDonationEntries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `DataDonationEntries` (
  `Id` binary(16) NOT NULL,
  `date` datetime(6) NOT NULL,
  `data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci,
  PRIMARY KEY (`Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `DataDonationEntries`
--

LOCK TABLES `DataDonationEntries` WRITE;
/*!40000 ALTER TABLE `DataDonationEntries` DISABLE KEYS */;
INSERT INTO `DataDonationEntries` VALUES (_binary 'y�B \�E�W\"�\�\�\�n','2022-11-14 23:33:08.928277','{\"encryptedAnswers\":\"Zo/xFXqAdbwzutXG4\\u002BqlcoWj\\u002BLXqzPpPtHFCHrCFpf\\u002BKLUQ0c57tBzAhiUct3ud0JhvoV3yZVQMjhfA9W2i\\u002BUZh2qGycuESBBrV9PGr4G\\u002Bkps/asVd8tt/SHUyz/6NT2Q423mCyZI9hORvkYL2nU5vYHwPYaFsjrzegGxyT5XgKY3n8inYtvUMeEFXXlQXNavCtRSOl6ibWkae81EgT68wIERv34LO5m0RngwANgqrUS0zbW3lVNEbrtSlyCAOtj/tn4KJnZYS\\u002Bn2C9JjZj2wiYSdoZ2vwoB6MmjoQr0tQt6hal4sErwCl79um\\u002BuGI1JEEbLYVj\\u002B7iKrduChfpXOJlo1bp38w0SyVJUeubcOcBTYd1s8eP8g05UFxZW\\u002BzZyucwS1jYIPVeuCnMVvK7sU94H\\u002B8Ehsupyvyt4wH82sxk0ofPZIVwnLZ51WCbFZY6bjZVA9q6gmGEkPTMQE8piQnQ==\",\"encryptedKey\":\"YsAcCpZhqtAY6Rtx4VPrNxGzYZsdr\\u002Bj2MGgwQHfIlHsYvms9yA5o4w4dDxumnv\\u002B5s8HD8aZMGO4YxZ6tG\\u002BxK9SiaxexV8MwT1U1QeB4JGb1Dt7YW9F7y19\\u002BgzRumvKS0xsiFosmzR/TtkBBYOPfcFaknUGAiBAeASJlEn6xxPP3pGJzxSl2srS9TH6FFG2\\u002Bdlt5Ci8Dg/2TfbpunU9Y83vUXLz4NakiR46wfBD/SLAwwDimuQ7I/DmjGQA6rLVvz6WXvA/XKT42SlbXKfoImRqlaNCR01dfXhn8cr/XjqfYzmEKcYFB\\u002BbBgc/nd\\u002B3vEqVZqyLCtX4lnXknZ4HCMs4g==\",\"iv\":\"u1fBPA6KtjlKYHOu\",\"signingKey\":\"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn5jt/YIC54/bRjkZlvW6DO1kW1svbdjE4K7FOlK0qv3NRHcS94Ie26WSjNeAg4pM3DEl8nSzP/QqbCd7OZhqMsEGJrZ0as59VOx6PvyClbkTi/FuUxlnPMudwrKIYELHEYTMqubqr81LG45ylrIX2pzXBZ5txas\\u002BnoBqkbdEaO\\u002B3A6e9sgPchk334phTTKQIHptOMmo4V86yVPnHXpGmbo32PX6pG8BZ0jlsUghH0e/B0s5DCI8L1cQs70OSQDDNN4f7kQaQWo4VfjHWLr0EvmlGG9XcEpc8ucup3/WmxT3HdZuUjdttLZ2/6KmbEcAt/wcdxxFKF6cB0dHkBPPubQIDAQAB-----END PUBLIC KEY-----\"}'),(_binary '\"�����?E�2p\"7%F','2022-11-14 23:33:00.759043','{\"encryptedAnswers\":\"Zo/xFXqAdbwzutXG4\\u002BqlcoWj\\u002BLXqzPpPtHFCHrCFpf\\u002BKLUQ0c57tBzAhiUct3ud0JhvoV3yZVQMjhfA9W2i\\u002BUZh2qGycuESBBrV9PGr4G\\u002Bkps/asVd8tt/SHUyz/6NT2Q423mCyZI9hORvkYL2nU5vYHwPYaFsjrzegGxyT5XgKY3n8inYtvUMeEFXXlQXNavCtRSOl6ibWkae81EgT68wIERv34LO5m0RngwANgqrUS0zbW3lVNEbrtSlyCAOtj/tn4KJnZYS\\u002Bn2C9JjZj2wiYSdoZ2vwoB6MmjoQr0tQt6hal4sErwCl79um\\u002BuGI1JEEbLYVj\\u002B7iKrduChfpXOJlo1bp38w0SyVJUeubcOcBTYd1s8eP8g05UFxZW\\u002BzZyucwS1jYIPVeuCnMVvK7sU94H\\u002B8Ehsupyvyt4wH82sxk0ofPZIVwnLZ51WCbFZY6bjZVA9q6gmGEkPTMQE8piQnQ==\",\"encryptedKey\":\"YsAcCpZhqtAY6Rtx4VPrNxGzYZsdr\\u002Bj2MGgwQHfIlHsYvms9yA5o4w4dDxumnv\\u002B5s8HD8aZMGO4YxZ6tG\\u002BxK9SiaxexV8MwT1U1QeB4JGb1Dt7YW9F7y19\\u002BgzRumvKS0xsiFosmzR/TtkBBYOPfcFaknUGAiBAeASJlEn6xxPP3pGJzxSl2srS9TH6FFG2\\u002Bdlt5Ci8Dg/2TfbpunU9Y83vUXLz4NakiR46wfBD/SLAwwDimuQ7I/DmjGQA6rLVvz6WXvA/XKT42SlbXKfoImRqlaNCR01dfXhn8cr/XjqfYzmEKcYFB\\u002BbBgc/nd\\u002B3vEqVZqyLCtX4lnXknZ4HCMs4g==\",\"iv\":\"u1fBPA6KtjlKYHOu\",\"signingKey\":\"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn5jt/YIC54/bRjkZlvW6DO1kW1svbdjE4K7FOlK0qv3NRHcS94Ie26WSjNeAg4pM3DEl8nSzP/QqbCd7OZhqMsEGJrZ0as59VOx6PvyClbkTi/FuUxlnPMudwrKIYELHEYTMqubqr81LG45ylrIX2pzXBZ5txas\\u002BnoBqkbdEaO\\u002B3A6e9sgPchk334phTTKQIHptOMmo4V86yVPnHXpGmbo32PX6pG8BZ0jlsUghH0e/B0s5DCI8L1cQs70OSQDDNN4f7kQaQWo4VfjHWLr0EvmlGG9XcEpc8ucup3/WmxT3HdZuUjdttLZ2/6KmbEcAt/wcdxxFKF6cB0dHkBPPubQIDAQAB-----END PUBLIC KEY-----\"}');
/*!40000 ALTER TABLE `DataDonationEntries` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `__EFMigrationsHistory`
--

DROP TABLE IF EXISTS `__EFMigrationsHistory`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `__EFMigrationsHistory` (
  `MigrationId` varchar(150) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `ProductVersion` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`MigrationId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `__EFMigrationsHistory`
--

LOCK TABLES `__EFMigrationsHistory` WRITE;
/*!40000 ALTER TABLE `__EFMigrationsHistory` DISABLE KEYS */;
INSERT INTO `__EFMigrationsHistory` VALUES ('20210723185816_Initial','6.0.7'),('20220517231840_dotnet-update','6.0.7');
/*!40000 ALTER TABLE `__EFMigrationsHistory` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-11-15  0:12:47
