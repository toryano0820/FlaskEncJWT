USE oauth;

CREATE TABLE IF NOT EXISTS `member` (
    `id` int AUTO_INCREMENT PRIMARY KEY,
    `first_name` tinytext NOT NULL,
    `last_name` tinytext NOT NULL,
    `email` tinytext NOT NULL,
    `password` tinytext NOT NULL,
    `date_registered` datetime NOT NULL
);

CREATE TABLE IF NOT EXISTS `auth_code` (
    `user_id` int,
    `code` int NOT NULL,
    `token` tinytext NOT NULL
);

CREATE TABLE IF NOT EXISTS `scope` (
    `user_id` int,
    `scope` tinytext NOT NULL
);

DROP PROCEDURE IF EXISTS add_scope;
CREATE PROCEDURE add_scope(_email TINYTEXT, _scope TINYTEXT)
BEGIN
    IF _scope IS NOT NULL AND _scope != '' THEN
        SET @scope = NULL;
        SET @user_id = -1;

        SELECT `id`, `scope`
        INTO @user_id, @scope
        FROM `member`
        LEFT JOIN `scope`
        ON `scope`.`user_id` = `member`.`id`
        WHERE `email` = _email;

        IF @user_id != -1 THEN
            IF @scope IS NULL THEN
                INSERT INTO `scope` (`user_id`, `scope`)
                VALUES (@user_id, _scope);
            ELSE
                UPDATE `scope`
                SET `scope` = CONCAT(@scope, ' ', _scope)
                WHERE `user_id` = @user_id;
            END IF;

            SELECT `id`, `scope`
            FROM `member`
            LEFT JOIN `scope`
            ON `scope`.`user_id` = `member`.`id`
            WHERE `email` = _email;
        END IF;
    END IF;
END;

DROP PROCEDURE IF EXISTS register;
CREATE PROCEDURE register(_email TINYTEXT, _password TINYTEXT, _first_name TINYTEXT, _last_name TINYTEXT)
BEGIN
    IF (SELECT COUNT(*) FROM member LIMIT 1) = 0 THEN
        INSERT INTO member (`email`, `password`, `first_name`, `last_name`, `date_registered`)
        VALUES (_email, SHA2(_password, 512), _first_name, _last_name, NOW());

        SET @_user_id = (SELECT `id` FROM `member` WHERE `email` = _email LIMIT 1);
        SELECT @_user_id;
    END IF;
END;

DROP PROCEDURE IF EXISTS authenticate;
CREATE PROCEDURE authenticate(_email TINYTEXT, _password TINYTEXT)
BEGIN
    SELECT `id`, `email`, `first_name`, `last_name`, `scope`.`scope`
    FROM `member`
    LEFT JOIN `scope`
    ON `scope`.`user_id` = `member`.`id`
    WHERE `email` = _email AND `password` = SHA2(_password, 512);
END;


-- DELETE FROM member;
-- CALL register('victormentoymacasaet@gmail.com', 'Cr123456', 'Victor', 'Macasaet');
-- CALL authenticate('victormentoymacasaet@gmail.com', 'Cr123456');
-- CALL add_scope('victormentoymacasaet@gmail.com', 'user:query')
-- SELECT * FROM member;

-- TODO: ADD_SCOPE, IGNORE IF EXISTING