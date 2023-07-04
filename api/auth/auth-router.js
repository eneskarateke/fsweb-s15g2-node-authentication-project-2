const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const jwt = require("jsonwebtoken");
const User = require("../users/users-model");
const bcryptjs = require("bcryptjs");

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
  try {
    let payload = {
      subject: req.currentUser.user_id,
      username: req.currentUser.username,
      role_name: req.currentUser.role_name,
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" });
    res.json({
      message: `${req.currentUser.username} geri geldi!`,
      token: token,
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
