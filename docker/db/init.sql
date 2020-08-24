USE oauth;
-- SET GLOBAL log_bin_trust_function_creators=1;

CREATE TABLE IF NOT EXISTS `app` (
    `id` tinytext UNIQUE NOT NULL,
    `name` tinytext NOT NULL,
    `description` tinytext NOT NULL,
    `redirect_uri` text NOT NULL,
    `date_registered` datetime NOT NULL
);


CREATE TABLE IF NOT EXISTS `member` (
    `id` tinytext UNIQUE NOT NULL,
    `email` tinytext NOT NULL UNIQUE,
    `password` tinytext NOT NULL,
    `first_name` tinytext NULL,
    `last_name` tinytext NULL,
    `date_registered` datetime NOT NULL,
    `scope` tinytext NULL
    `owner` tinytext NULL,
);

CREATE TABLE IF NOT EXISTS `auth_code` (
    `user_id` int NOT NULL,
    `code` tinytext NOT NULL,
    `signed_state` tinytext NOT NULL
);

DROP FUNCTION IF EXISTS IS_EMAIL;
CREATE FUNCTION IS_EMAIL(_email tinytext)
RETURNS int DETERMINISTIC
BEGIN
    SET @retval = (SELECT REGEXP_LIKE(_email, '^[A-Za-z0-9]+([._][A-Za-z0-9]+)*@[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$'));
    RETURN @retval;
END;

DROP PROCEDURE IF EXISTS add_scope;
CREATE PROCEDURE add_scope(_email tinytext, _scope tinytext)
BEGIN
    IF (SELECT COUNT(*) FROM `member` WHERE `email` = _email LIMIT 1) = 1 THEN
        SET @scope = (SELECT `scope` FROM `member` WHERE `email` = _email);

        IF INSTR(@scope, _scope) = 0 THEN
            SET @scope = CONCAT(@scope, ' ', _scope);
            UPDATE `member`
            SET `scope` = @scope
            WHERE `email` = _email;
        END IF;

        SELECT @scope;
    END IF;
END;

DROP PROCEDURE IF EXISTS register;
CREATE PROCEDURE register(_owner tinytext, _email tinytext, _password tinytext, _first_name tinytext, _last_name tinytext)
BEGIN
    IF ((_owner IS NULL AND IS_EMAIL(_email) = 1) OR (SELECT COUNT(*) FROM member WHERE email = _owner LIMIT 1) = 1)
            AND ((SELECT COUNT(*) FROM member WHERE email = _email LIMIT 1) = 0) THEN
        INSERT INTO member (`owner`, `email`, `password`, `first_name`, `last_name`, `date_registered`)
        VALUES (_owner, _email, SHA2(CONCAT(_email, _password), 512), _first_name, _last_name, NOW());

        SELECT `id` FROM `member` WHERE `email` = _email LIMIT 1;
    END IF;
END;

-- DROP PROCEDURE IF EXISTS change_password;
-- CREATE PROCEDURE change_password(_email tinytext, _password tinytext)
-- BEGIN
--     IF (SELECT COUNT(*) FROM `member` WHERE `email`=_email LIMIT 1) = 1 THEN
--         UPDATE `member`
--         SET `password` = SHA2(CONCAT(_email, _password), 512)
--         WHERE `email` = _email;

--         SELECT `id` FROM `member` WHERE `email` = _email LIMIT 1;
--     END IF;
-- END;

DROP PROCEDURE IF EXISTS authenticate;
CREATE PROCEDURE authenticate(_email tinytext, _password tinytext, _state tinytext)
BEGIN
    SET @code = NULL;
    SET @user_id = -1;
    SET @first_name = NULL;
    SET @last_name = NULL;

    SELECT `id`, `first_name`, `last_name`
    INTO @user_id, @first_name, @last_name
    FROM `member`
    WHERE `email` = _email AND `password` = SHA2(CONCAT(_email, _password), 512)
    LIMIT 1;

    IF @user_id != -1 THEN
        DELETE FROM `auth_code` WHERE `user_id` = @user_id;

        while_true: LOOP
            SET @code = MD5(RAND());

            IF (SELECT COUNT(*) FROM `auth_code` WHERE `code` = @code LIMIT 1) = 0 THEN
                LEAVE while_true;
            END IF;
        END LOOP;

        INSERT INTO `auth_code` (`user_id`, `code`, `state`, `date_generated`)
        VALUES (@user_id, @code, _state, NOW());

        SELECT @code;
    END IF;
END;

DROP PROCEDURE IF EXISTS validate_auth_code;
CREATE PROCEDURE validate_auth_code(_code tinytext)
BEGIN
    SELECT `state`
    FROM `auth_code`
    WHERE `code` = _code;

    DELETE FROM `auth_code`
    WHERE `code` = _code;
END;


-- USE oauth;

-- SELECT * FROM member;
-- SELECT * FROM scope;
-- SELECT * FROM auth_code;
-- DELETE FROM member;
-- DELETE FROM scope;
-- DROP TABLE auth_code;
-- CALL register(NULL, 'victormentoymacasaet@gmail.com', 'Cr123456', 'Victor', 'Macasaet');
-- CALL register('victormentoymacasaet@gmail.com', 'kpphtl', 'Cr123456', NULL, NULL);
-- CALL authenticate('victormentoymacasaet@gmail.com', 'Cr123456', 'samplestate12123123123');
-- CALL validate_auth_code('a77e7f7c0b7ac9560fcdf2ab83c81976');
-- CALL authenticate('victormentoymacasaet@gmail.com', 'Cr123456');
-- CALL add_scope('victormentoymacasaet@gmail.com', 'vuser:add');
-- CALL get_auth_code('victormentoymacasaet@gmail.com', 'sample token');
-- CALL get_code_token('384685');
-- SELECT * FROM member;

-- CALL is_email('1@1.1.1.1');
-- SELECT CURRENT_TIMESTAMP;
-- SELECT NOW() + INTERVAL 0.1 SECOND;

-- DROP TABLE auth_code;
-- DROP TABLE member;
-- DROP TABLE scope;
-- DROP PROCEDURE add_scope;
-- DROP PROCEDURE authenticate;
-- DROP PROCEDURE change_password;
-- DROP PROCEDURE get_code_token;
-- DROP PROCEDURE register;