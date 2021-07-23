const router = require('express').Router()
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const Users = require("./users-model")
const { restrict } = require("./users-middleware")


router.post('/register', (req, res) => {
  res.end('implement register, please!');
  /*
    IMPLEMENT
    You are welcome to build additional middlewares to help with the endpoint's functionality.
    DO NOT EXCEED 2^8 ROUNDS OF HASHING!

    1- In order to register a new account the client must provide `username` and `password`:
      {
        "username": "Captain Marvel", // must not exist already in the `users` table
        "password": "foobar"          // needs to be hashed before it's saved
      }

    2- On SUCCESSFUL registration,
      the response body should have `id`, `username` and `password`:
      {
        "id": 1,
        "username": "Captain Marvel",
        "password": "2a$08$jG.wIGR2S4hxuyWNcBf9MuoC4y0dNy7qC/LbmtuFBSdIhWks2LhpG"
      }

    3- On FAILED registration due to `username` or `password` missing from the request body,
      the response body should include a string exactly as follows: "username and password required".

    4- On FAILED registration due to the `username` being taken,
      the response body should include a string exactly as follows: "username taken".
  */
});


router.get("/users", restrict(), async (req, res, next) => {
  try {
      res.json(await Users.find())
  } catch(err) {
      next(err)
  }
})

router.post("/login", async (req, res, next)=>{
  try {
      const { username, password } = req.body
  const user = await Users.findByUsername(username)

  if (!user) {
    return res.status(401).json({
      message: "Invalid Credentials",
    })
      }
      const passwordValid = await bcrypt.compare(password, user.password)

  if (!passwordValid) {
    return res.status(401).json({
      message: "Invalid Credentials",
    })
      }
      const token = jwt.sign({
    userID: user.id,
    userDepartment: user.department,

      }, process.env.JWT_SECRET)

      res.cookie("token", token)

  res.json({
    message: `Welcome ${user.username}!`,
  })

  } catch(err) {
      next(err)
  }
});

router.post('/login', (req, res) => {
  res.end('implement login, please!');
  /*
    IMPLEMENT
    You are welcome to build additional middlewares to help with the endpoint's functionality.

    1- In order to log into an existing account the client must provide `username` and `password`:
      {
        "username": "Captain Marvel",
        "password": "foobar"
      }

    2- On SUCCESSFUL login,
      the response body should have `message` and `token`:
      {
        "message": "welcome, Captain Marvel",
        "token": "eyJhbGciOiJIUzI ... ETC ... vUPjZYDSa46Nwz8"
      }

    3- On FAILED login due to `username` or `password` missing from the request body,
      the response body should include a string exactly as follows: "username and password required".

    4- On FAILED login due to `username` not existing in the db, or `password` being incorrect,
      the response body should include a string exactly as follows: "invalid credentials".
  */
});

router.post("/register", async (req, res, next)=>{
  try {
      const { username, password, department } = req.body
      const user = await Users.findByUsername(username)

      if (user) {
    return res.status(409).json({
      message: "Username is already taken",
    })
      }

      const newUser = await Users.add({
          username,
          department,
          password: await bcrypt.hash(password, 14)
      })

      res.status(201).json(newUser)
  } catch(err) {
      next(err)
  }
});

router.get("/logout", async (req, res, next) => {
	try {
		req.session.destroy((err) => {
			if (err) {
				next(err)
			} else {
				res.status(204).end()
			}
		})
	} catch (err) {
		next(err)
	}
})

module.exports = router;
