-- Usar la base de datos
USE login_seguridad;

-- Crear la tabla "user"
CREATE TABLE IF NOT EXISTS user (
  id SMALLINT(3) UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(30) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  password CHAR(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  fullname VARCHAR(60) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (id));

-- Insertar un nuevo usuario en la tabla "user"
-- Hola
INSERT INTO user (username, password, fullname) VALUES ('Jp', 'scrypt:32768:8:1$EHmbQYumOGlf3tcL$b99cd68572f6623cc821c19b82f300a6b44f279b9315a9eae27717fc34557ef487dc48dc93cc895df2fafb3bd66603cc711319dc978d93e062f839145834e7bd', 'JpVelasquezC');
-- \<UrY$*>Q9v9
INSERT INTO user (username, password, fullname) VALUES ('Velasquez', 'scrypt:32768:8:1$W0kF8m81vZoqliPV$4868617c1a08aedf0bebb67ef1f2078fb7fd575afb0311666f34f0a9e43736a6f2ef66b5a5546c7723c21798dff9066e1bd79ab12c2ceb8ac3aa0ae3a4bbcbce', 'Credencial 1');
-- j$9@eN$dct\z
INSERT INTO user (username, password, fullname) VALUES ('AlfredoTamarindo', 'scrypt:32768:8:1$r1TnxqMAQFc47hUA$ff1a1b4e5159f3a198d5b24fe0ca3d339fccf64b19cc4814fab75859b5c5d2eb9c7ec7fd294f688ebcd89635bea3e9663c798dcf03ce4f5efe3c8fdda685f41f', 'Credencial 2');
-- Lo;E{H\-pqZ>
INSERT INTO user (username, password, fullname) VALUES ('BobConstructor', 'scrypt:32768:8:1$RdRqYcBLxD8gP7BA$bdf1fb54e4cb7a46f22790877fcb84f36ac6aab0cdee3dca6170ab4cb37937f889d1839bdf1035a5505c1a9d54e0ed783452bc50a8a9c72b4699abf6e4fa6131', 'Credencial 3');

SELECT * FROM login_seguridad.user; -- WHERE id != ;
