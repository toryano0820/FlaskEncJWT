SET GLOBAL max_connections = 1024;
SET GLOBAL log_bin_trust_function_creators = 1;

USE oauth;

DROP TABLE IF EXISTS client;
DROP TABLE IF EXISTS member;
DROP TABLE IF EXISTS code;


CREATE TABLE IF NOT EXISTS `member` (
    `id` INT PRIMARY KEY AUTO_INCREMENT,
    `email` VARCHAR(512) UNIQUE NOT NULL,
    `password` VARCHAR(128) NOT NULL,
    `display_name` NVARCHAR(64) NOT NULL,
    `full_name` NVARCHAR(256) NOT NULL,
    `date_created` DATETIME NOT NULL,
    `permission` VARCHAR(10) NULL  -- NULL|read|write|root
);

CREATE TABLE IF NOT EXISTS `client` (
    `id` VARCHAR(64) UNIQUE NOT NULL,
    `secret` VARCHAR(32) NOT NULL,
    `member_id` INT NOT NULL,
    `name` VARCHAR(256) NOT NULL,
    `authorized_hosts` VARCHAR(512) NOT NULL,
    `date_created` DATETIME NOT NULL,
    `state` VARCHAR(10) NULL  -- NULL|inactive|active
);

CREATE TABLE IF NOT EXISTS `code` (
    `id` INT PRIMARY KEY AUTO_INCREMENT,
    `member_id` INT NOT NULL,
    `code` VARCHAR(32) UNIQUE NOT NULL,
    `payload` LONGTEXT NULL,
    `date_created` DATETIME NOT NULL
);

-- DROP FUNCTION IF EXISTS is_email;
-- CREATE FUNCTION is_email(_email VARCHAR(512))
-- RETURNS INT DETERMINISTIC
-- BEGIN
--     SET @retval = (SELECT REGEXP_LIKE(_email, '^[A-Za-z0-9]+([._][A-Za-z0-9]+)*@[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$'));
--     RETURN @retval;
-- END;

DELIMITER //

DROP PROCEDURE IF EXISTS register_member //
CREATE PROCEDURE register_member(_email VARCHAR(512), _password VARCHAR(128), _display_name VARCHAR(64), _full_name VARCHAR(256))
BEGIN
    IF (SELECT COUNT(*) FROM `member` WHERE `email` = _email LIMIT 1) = 1 THEN
        SELECT 'member_exists' as `error`;
    ELSE
        INSERT INTO `member` (`email`, `password`, `display_name`, `full_name`, `date_created`)
        VALUES (_email, SHA2(CONCAT(_email, ':', _password), 512), _display_name, _full_name, NOW());
        COMMIT;

        SET @member_id = LAST_INSERT_ID();
        SET @code = NULL;
        CALL generate_code_byref(@member_id, NULL, @code);
        SELECT @code as `code`, @member_id as `member_id`;
    END IF;
END //

DROP PROCEDURE IF EXISTS set_permission //
CREATE PROCEDURE set_permission(_email VARCHAR(512), _permission VARCHAR(10))
BEGIN
    IF (SELECT COUNT(*) FROM `member` WHERE `email` = _email LIMIT 1) = 0 THEN
        SELECT 'member_not_found' as `error`;
    ELSE
        UPDATE `member`
        SET `permission` = _permission
        WHERE `email` = _email;
        COMMIT;

        SELECT _permission as `permission`;
    END IF;
END //

DROP PROCEDURE IF EXISTS register_client //
CREATE PROCEDURE register_client(_email VARCHAR(512), _name VARCHAR(256), _authorized_hosts VARCHAR(512))
BEGIN
    SET @client_id = SHA2(CONCAT(_email, ':', _name), 256);
    SET @client_secret = MD5(RAND());
    SET @member_id = (SELECT `id` FROM `member` WHERE `email` = _email LIMIT 1);

    IF @member_id IS NULL THEN
        SELECT 'member_not_found' as `error`;
    ELSEIF (SELECT COUNT(*) FROM `client` WHERE `id` = @client_id LIMIT 1) = 1 THEN
        SELECT 'client_exists' as `error`;
    ELSE
        INSERT INTO `client` (`member_id`, `id`, `secret`, `name`, `authorized_hosts`, `date_created`)
        VALUES (@member_id, @client_id, @client_secret, _name, _authorized_hosts, NOW());
        COMMIT;

        SELECT @client_id as `client_id`, @client_secret as `client_secret`, _name as `name`, _email as `email`;
    END IF;
END //

DROP PROCEDURE IF EXISTS set_state //
CREATE PROCEDURE set_state(_client_id VARCHAR(512), _state VARCHAR(10))
BEGIN
    IF (SELECT COUNT(*) FROM `client` WHERE `id` = _client_id LIMIT 1) = 0 THEN
        SELECT 'client_not_found' as `error`;
    ELSE
        UPDATE `client`
        SET `state` = _state
        WHERE `id` = _client_id;
        COMMIT;

        SELECT _state as `state`;
    END IF;
END //

DROP PROCEDURE IF EXISTS change_password //
CREATE PROCEDURE change_password(_email VARCHAR(512), _password VARCHAR(1024))
BEGIN
    SET @member_id = (SELECT `id` FROM `member` WHERE `email` = _email);

    IF @member_id IS NULL THEN
        SELECT 'member_not_found' as `error`;
    ELSE
        UPDATE `member`
        SET `password` = SHA2(CONCAT(_email, ':', _password), 512)
        WHERE `email` = _email;
        COMMIT;

        SELECT @member_id as `member_id`;
    END IF;
END //

DROP PROCEDURE IF EXISTS authenticate //
CREATE PROCEDURE authenticate(_email VARCHAR(512), _password VARCHAR(128), _payload LONGTEXT)
BEGIN
    SET @code = NULL;
    SET @member_id = NULL;
    SET @display_name = NULL;
    SET @full_name = NULL;
    SET @password = NULL;

    SELECT `id`, `display_name`, `full_name`, `password`
    INTO @member_id, @display_name, @full_name, @password
    FROM `member`
    WHERE `email` = _email
    LIMIT 1;

    IF @member_id IS NULL THEN
        SELECT 'member_not_found' as `error`;
    ELSEIF @password != SHA2(CONCAT(_email, ':', _password), 512) THEN
        SELECT 'password_incorrect' as `error`;
    ELSE
        SET @code = NULL;
        CALL generate_code_byref(@member_id, _payload, @code);
        SELECT @code as `code`, @member_id as `member_id`;
    END IF;
END //

DROP PROCEDURE IF EXISTS generate_code_byref //
CREATE PROCEDURE generate_code_byref(_member_id INT, _payload LONGTEXT, OUT _code VARCHAR(32))
BEGIN
    while_true: LOOP
        SET @code = MD5(RAND());

        IF (SELECT COUNT(*) FROM `code` WHERE `code` = @code LIMIT 1) = 0 THEN
            LEAVE while_true;
        END IF;
    END LOOP;

    DELETE FROM `code` WHERE `member_id` = _member_id;
    COMMIT;

    INSERT INTO `code` (`member_id`, `code`, `payload`, `date_created`)
    VALUES (_member_id, @code, _payload, NOW());
    COMMIT;

    SELECT @code INTO _code;
END //

DROP PROCEDURE IF EXISTS generate_code //
CREATE PROCEDURE generate_code(_member_id INT, _payload LONGTEXT)
BEGIN
    SET @code = NULL;
    CALL generate_code_byref(_member_id, _payload, @code);
    SELECT @code as `code`;
END //

DROP PROCEDURE IF EXISTS validate_code //
CREATE PROCEDURE validate_code(_code VARCHAR(32))
BEGIN
    SET @member_id = NULL;
    SET @payload = NULL;
    SET @date_created = NULL;

    SELECT `member_id`, `payload`, `date_created`
    INTO @member_id, @payload, @date_created
    FROM `code`
    WHERE `code` = _code
    LIMIT 1;

    IF @member_id IS NULL THEN
        SELECT 'code_not_found' as `error`;
    ELSEIF NOW() > @date_created + INTERVAL 30 MINUTE THEN
        SELECT 'code_expired' as `error`;
    ELSE
        SELECT @member_id as `member_id`, @payload as `payload`, `email`, `display_name`
        FROM `member`
        WHERE `id` = @member_id;
    END IF;

    DELETE FROM `code`
    WHERE `member_id` = @member_id;
    COMMIT;
END //

DROP PROCEDURE IF EXISTS get_member_info //
CREATE PROCEDURE get_member_info(_email VARCHAR(512))
BEGIN
    IF (SELECT COUNT(*) FROM `member` WHERE `email` = _email LIMIT 1) = 0 THEN
        SELECT 'member_not_found' as `error`;
    ELSE
        SELECT `id`, `email`, `display_name`, `full_name`, `permission` FROM `member` WHERE `email` = _email LIMIT 1;
    END IF;
END //

DROP PROCEDURE IF EXISTS get_client_info //
CREATE PROCEDURE get_client_info(_client_id VARCHAR(64))
BEGIN
    IF (SELECT COUNT(*) FROM `client` WHERE `id` = _client_id LIMIT 1) = 0 THEN
        SELECT 'client_not_found' as `error`;
    ELSE
        SELECT `client`.`id` as `client_id`, `client`.`secret` as `client_secret`, `name`, `email`, `display_name` as `member_name`, `state`
        FROM `client`
        LEFT JOIN `member`
        ON `client`.`member_id` = `member`.`id`
        WHERE `client`.`id` = _client_id LIMIT 1;
    END IF;
END //

DELIMITER ;
