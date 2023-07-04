const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const jwt = require("jsonwebtoken");
const User = require("../users/users-model");

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const user = req.body;
  user.password = bcryptjs.hashSync(user.password, 8); // 2 üzeri 8 defa hashleyecek.
  const newUser = await User.ekle(user);
  if (newUser) {
    res.status(201).json(newUser);
  } else {
    next();
  }
});

router.post("/login", usernameVarmi, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
  const { password, username } = req.body;
  // adım 1: önce kişiyi veritabanından alırız.
  const user = await User.goreBul({ Email: Email }).first();
  //adım 2: password'unu check ederiz.
  if (user && bcrypt.compareSync(password, user.password)) {
    //req.session.user = user;  //Session oluşturduk.
    const token = generateToken(user);
    res.json({ message: `${user.username} geri geldi!`, token });
  } else {
    res.status(401).json({ message: `Giriş bilgileri yanlış...` });
  }
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "1d",
  };
  const token = jwt.sign(payload, JWT_SECRET, options);
  return token;
}

module.exports = router;
