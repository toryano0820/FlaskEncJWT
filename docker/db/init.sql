SET GLOBAL max_connections = 1024;

USE oauth;

DROP TABLE IF EXISTS app;
DROP TABLE IF EXISTS member;
DROP TABLE IF EXISTS auth_code;


CREATE TABLE IF NOT EXISTS `app` (
    `id` int PRIMARY KEY AUTO_INCREMENT,
    `client_id` varchar(64) UNIQUE NOT NULL,
    `name` varchar(256) NOT NULL,
    `description` varchar(512) NULL,
    `redirect_uri` varchar(512) NOT NULL,
    `date_created` datetime NOT NULL
);

CREATE TABLE IF NOT EXISTS `member` (
    `id` int PRIMARY KEY AUTO_INCREMENT,
    `email` varchar(512) UNIQUE NOT NULL,
    `password` varchar(128) NOT NULL,
    `display_name` nvarchar(64) NOT NULL,
    `full_name` nvarchar(256) NOT NULL,
    `date_created` datetime NOT NULL,
    `scope` varchar(512) NULL -- NULL|read|write|root
);

CREATE TABLE IF NOT EXISTS `auth_code` (
    `id` int PRIMARY KEY AUTO_INCREMENT,
    `member_id` int NOT NULL,
    `code` varchar(32) UNIQUE NOT NULL,
    `payload` json NULL,
    `date_created` datetime NOT NULL
);

-- DROP FUNCTION IF EXISTS is_email;
-- CREATE FUNCTION is_email(_email varchar(512))
-- RETURNS int DETERMINISTIC
-- BEGIN
--     SET @retval = (SELECT REGEXP_LIKE(_email, '^[A-Za-z0-9]+([._][A-Za-z0-9]+)*@[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$'));
--     RETURN @retval;
-- END;

DELIMITER //

DROP PROCEDURE IF EXISTS set_auth_code //
CREATE PROCEDURE set_auth_code(IN _member_id int, OUT _code varchar(32))
BEGIN
    while_true: LOOP
        SET @code = MD5(RAND());

        IF (SELECT COUNT(*) FROM `auth_code` WHERE `code` = @code LIMIT 1) = 0 THEN
            LEAVE while_true;
        END IF;
    END LOOP;

    SELECT @code INTO _code;

    INSERT INTO `auth_code` (`member_id`, `code`, `date_created`)
    VALUES (@member_id, @code, NOW());
    COMMIT;
END //

DROP PROCEDURE IF EXISTS add_scope //
CREATE PROCEDURE add_scope(_email varchar(512), _scope varchar(32))
BEGIN
    IF (SELECT COUNT(*) FROM `member` WHERE `email` = _email LIMIT 1) = 0 THEN
        SELECT 'email_not_found' as `error`;
    ELSE
        SET @scope = (SELECT `scope` FROM `member` WHERE `email` = _email LIMIT 1);

        IF @scope IS NULL OR INSTR(@scope, _scope) = 0 THEN
            SET @scope = CONCAT(@scope, ' ', _scope);

            UPDATE `member`
            SET `scope` = @scope
            WHERE `email` = _email;
            COMMIT;
        END IF;

        SELECT @scope as `scope`;
    END IF;
END //

DROP PROCEDURE IF EXISTS register_member //
CREATE PROCEDURE register_member(_email varchar(512), _password varchar(128), _display_name varchar(64), _full_name varchar(256))
BEGIN
    IF (SELECT COUNT(*) FROM `member` WHERE `email` = _email LIMIT 1) = 1 THEN
        SELECT 'email_exists' as `error`;
    ELSEIF (SELECT `scope` FROM `member` WHERE `email` = _email LIMIT 1) IS NULL THEN
        INSERT INTO `member` (`email`, `password`, `display_name`, `full_name`, `date_created`)
        VALUES (_email, SHA2(CONCAT(_email, _password), 512), _display_name, _full_name, NOW());
        COMMIT;

        SET @member_id = LAST_INSERT_ID();
        SET @code = NULL;
        CALL set_auth_code(@member_id, @code);
        SELECT @code as `code`, @member_id as `member_id`;
    END IF;
END //

DROP PROCEDURE IF EXISTS register_app //
CREATE PROCEDURE register_app(_client_id varchar(64), _name varchar(256), _description varchar(512), _redirect_uri varchar(512))
BEGIN
    IF (SELECT COUNT(*) FROM `app` WHERE `client_id` = _client_id LIMIT 1) = 1 THEN
        SELECT 'client_exists' as `error`;
    ELSE
        INSERT INTO `app` (`client_id`, `name`, `description`, `redirect_uri`, `date_created`)
        VALUES (_client_id, _name, _description, _redirect_uri, NOW());
        COMMIT;

        SELECT `id` FROM `app` WHERE `client_id` = _client_id LIMIT 1;
    END IF;
END //

DROP PROCEDURE IF EXISTS change_password //
CREATE PROCEDURE change_password(_email tinytext, _password tinytext)
BEGIN
    IF (SELECT COUNT(*) FROM `member` WHERE `email`=_email LIMIT 1) = 1 THEN
        UPDATE `member`
        SET `password` = SHA2(CONCAT(_email, _password), 512)
        WHERE `email` = _email;

        SELECT `id` as `member_id` FROM `member` WHERE `email` = _email LIMIT 1;
    END IF;
END //

DROP PROCEDURE IF EXISTS authenticate //
CREATE PROCEDURE authenticate(_email varchar(512), _password varchar(128))
BEGIN
    SET @code = NULL;
    SET @member_id = -1;
    SET @display_name = NULL;
    SET @full_name = NULL;
    SET @password = NULL;

    SELECT `id`, `display_name`, `full_name`, `password`
    INTO @member_id, @display_name, @full_name, @password
    FROM `member`
    WHERE `email` = _email
    LIMIT 1;

    IF @member_id = -1 THEN
        SELECT 'email_not_found' as `error`;
    ELSEIF @password != SHA2(CONCAT(_email, _password), 512) THEN
        SELECT 'password_incorrect' as `error`;
    ELSE
        SET @code = NULL;
        CALL set_auth_code(@member_id, @code);
        SELECT @code as `code`, @member_id as `member_id`;
    END IF;
END //

DROP PROCEDURE IF EXISTS validate_code //
CREATE PROCEDURE validate_code(_code varchar(32))
BEGIN
    SET @member_id = -1;
    SET @date_created = NULL;

    SELECT `member_id`, `date_created`
    INTO @member_id, @date_created
    FROM `auth_code`
    WHERE `code` = _code
    LIMIT 1;

    IF @member_id = -1 THEN
        SELECT 'code_not_found' as `error`;
    ELSEIF NOW() > @date_created + INTERVAL 10 MINUTE THEN
        SELECT 'code_expired' as `error`;
    ELSE
        SELECT `id` as `member_id`, `display_name`, `email` FROM `member` WHERE `id` = @member_id;
    END IF;

    DELETE FROM `auth_code`
    WHERE `code` = _code;
    COMMIT;
END //

DROP PROCEDURE IF EXISTS reset_code //
CREATE PROCEDURE reset_code(_email varchar(512))
BEGIN
    SET @member_id = -1;

    SELECT `id`
    INTO @member_id
    FROM `member`
    WHERE `email` = _email
    LIMIT 1;

    IF @member_id = -1 THEN
        SELECT 'email_not_found' as `error`;
    ELSE
        SET @code = NULL;
        CALL set_auth_code(@member_id, @code);
        SELECT @code as `code`, @member_id as `member_id`;
    END IF;
END //

DELIMITER ;
