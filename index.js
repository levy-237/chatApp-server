const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const User = require("./models/User");
const Message = require("./models/Message");
const jwt = require("jsonwebtoken");
const app = express();
const ws = require("ws");
app.use(express.json());
app.use(cookieParser());
const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(9);
mongoose.connect(process.env.MONGO_URI);
const corsOptions = {
  origin: process.env.CLIENT_URL,
  credentials: true,
};
app.use(cors(corsOptions));
app.get("/test", async (req, res) => {
  const allUsers = await User.find({});
  res.status(201).json({ allUsers });
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies || {};
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, userInfo) => {
      if (err) {
        res.status(403).json("invalid token");
      } else {
        res.json(userInfo);
      }
    });
  } else {
    res.status(403).json("no token");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user) {
      const passCorrect = bcrypt.compareSync(password, user.password);
      if (passCorrect) {
        const token = await jwt.sign({ userId: user._id, username }, jwtSecret);
        res
          .cookie("token", token, { sameSite: "none", secure: true })
          .status(201)
          .json({
            id: user._id,
          });
      }
    }
  } catch (error) {
    res.status(400).send(error);
  }
});

app.post("/logout", (req, res) => {
  res.cookie("token", "", { sameSite: "none", secure: true }).json("success");
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPass = bcrypt.hashSync(password, bcryptSalt);
    const user = await User.create({
      username,
      password: hashedPass,
    });
    const token = await jwt.sign({ userId: user._id, username }, jwtSecret);
    res
      .cookie("token", token, { sameSite: "none", secure: true })
      .status(201)
      .json({
        id: user._id,
      });
  } catch (error) {
    res.status(400).send(error);
  }
});

app.get("/messages", async (req, res) => {
  const message = await Message.find({});
  res.json({ message });
});

app.get("/messages/:id", async (req, res) => {
  try {
    const { text } = req.query;
    const { id } = req.params;
    const token = req.cookies?.token;

    if (token) {
      const data = await jwt.verify(token, jwtSecret);

      const { userId, username } = data;

      const filter = {
        $or: [
          { sender: userId, recipient: id },
          { sender: id, recipient: userId },
        ],
      };

      if (text) {
        filter.text = { $regex: text, $options: "i" };
      }

      const messages = await Message.find(filter).sort({ createdAt: 1 }).exec();

      res.json(messages);
    } else {
      res.status(401).json({ error: "Unauthorized" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// app.get("/people", async (req, res) => {
//   const people = await User.find({});
//   res.json(people);
// });

app.get("/people", async (req, res) => {
  try {
    const { username } = req.query;
    const queryObj = {};

    if (username) {
      queryObj.username = new RegExp(username, "i");
    }

    const foundUsers = await User.find(queryObj);

    res.status(200).json(foundUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// app.get("/deleteall", async (req, res) => {
//   await User.deleteMany({});
//   await Message.deleteMany({});
//   res.status(200).json({ msg: "deleted" });
// });
const port = process.env.PORT || 4000;
const server = app.listen(port, () => {
  console.log("LISTENING ON PORT 4000");
});

const wss = new ws.WebSocketServer({ server });

wss.on("connection", (connection, req) => {
  const onlinePppNoti = () => {
    [...wss.clients].forEach((client) => {
      client.send(
        JSON.stringify({
          online: [...wss.clients].map((c) => ({
            userId: c.userId,
            username: c.username,
          })),
        })
      );
    });
  };

  connection.isAlive = true;

  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      onlinePppNoti();
    }, 2000);
  }, 4000);

  connection.on("pong", () => {
    clearTimeout(connection.deathTimer);
  });
  ///reading username and id for connection
  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies
      .split(";")
      .find((str) => str.startsWith("token="));
    if (tokenCookieString) {
      const token = tokenCookieString.split("=")[1];
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, data) => {
          if (err) throw err;
          const { userId, username } = data;
          connection.userId = userId;
          connection.username = username;
        });
      }
    }
  }
  connection.on("message", async (message) => {
    const messageData = JSON.parse(message.toString());
    const { text, recipient } = messageData;
    if (recipient && text) {
      const messageDoc = await Message.create({
        sender: connection.userId,
        recipient,
        text,
      });
      [...wss.clients]
        .filter((client) => client.userId === recipient)
        .forEach((client) =>
          client.send(
            JSON.stringify({
              text,
              sender: connection.userId,
              recipient,
              _id: messageDoc._id,
            })
          )
        );
    }
  });
  // displaying online users
  [...wss.clients].forEach((client) => {
    client.send(
      JSON.stringify({
        online: [...wss.clients].map((c) => ({
          userId: c.userId,
          username: c.username,
        })),
      })
    );
  });
  onlinePppNoti();
});
