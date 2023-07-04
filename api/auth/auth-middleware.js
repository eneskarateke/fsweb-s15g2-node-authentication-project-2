const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const jwt = require("jsonwebtoken");

const UserModel = require("../users/users-model");

const sinirli = (req, res, next) => {
  /*
    Eğer Authorization header'ında bir token sağlanmamışsa:
    status: 401
    {
      "message": "Token gereklidir"
    }

    Eğer token doğrulanamıyorsa:
    status: 401
    {
      "message": "Token gecersizdir"
    }

    Alt akıştaki middlewarelar için hayatı kolaylaştırmak için kodu çözülmüş tokeni req nesnesine koyun!
  */
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decodedJWT) => {
      if (err) {
        next({ status: 401, message: "Token gerçersizidir" });
      } else {
        req.decodedJWT = decodedJWT;
        next();
      }
    });
  } else {
    next({ status: 401, message: "Token gereklidir" });
  }
};

const sadece = (role_name) => (req, res, next) => {
  /*
    
	Kullanıcı, Authorization headerında, kendi payloadu içinde bu fonksiyona bağımsız değişken olarak iletilen 
	rol_adı ile eşleşen bir role_name ile bir token sağlamazsa:
    status: 403
    {
      "message": "Bu, senin için değil"
    }

    Tekrar authorize etmekten kaçınmak için kodu çözülmüş tokeni req nesnesinden çekin!
  */
  if (req.decodedJWT && req.decodedJWT.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: "Bu, senin için değil" });
  }
};

const usernameVarmi = async (req, res, next) => {
  /*
    req.body de verilen username veritabanında yoksa
    status: 401
    {
      "message": "Geçersiz kriter"
    }
  */
  try {
    const { password, username } = req.body;
    // adım 1: önce kişiyi veritabanından alırız.
    const user = await UserModel.goreBul({ username: username }).first();
    //adım 2: password'unu check ederiz.
    if (user && bcryptjs.compareSync(password, user.password)) {
      req.dbUser = user; //Session oluşturduk.
      next();
    } else {
      res.status(401).json({
        message: "Geçersiz kriter",
      });
    }
  } catch (error) {
    next(error);
  }
};

const rolAdiGecerlimi = (req, res, next) => {
  /*
    Bodydeki role_name geçerliyse, req.role_name öğesini trimleyin ve devam edin.

    Req.body'de role_name eksikse veya trimden sonra sadece boş bir string kaldıysa,
    req.role_name öğesini "student" olarak ayarlayın ve isteğin devam etmesine izin verin.

    Stringi trimledikten sonra kalan role_name 'admin' ise:
    status: 422
    {
      "message": "Rol adı admin olamaz"
    }

    Trimden sonra rol adı 32 karakterden fazlaysa:
    status: 422
    {
      "message": "rol adı 32 karakterden fazla olamaz"
    }
  */
  const { role_name } = req.body;

  if (role_name && role_name.trim().length > 0) {
    req.role_name = role_name.trim();
    next();
  } else {
    req.role_name = "student";
    next();
  }

  if (req.role_name === "admin") {
    return res.status(422).json({ message: "Rol adı admin olamaz" });
  }

  if (req.role_name.length > 32) {
    return res
      .status(422)
      .json({ message: "rol adı 32 karakterden fazla olamaz" });
  }
};

module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
};
