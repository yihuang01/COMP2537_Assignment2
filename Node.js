require("dotenv").config();

const url = require("url");

const express = require("express");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const mongoSanitizer = require("mongo-sanitizer").default;
const mongoURI = process.env.mongoURI;

const app = express();

const saltRounds = 10;
const PORT = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour in MILLISECONDS

app.set("view engine", "ejs");

const navLinks = [
  { name: "Home", url: "/" },
  { name: "Signup", url: "/signup" },
  { name: "Login", url: "/login" },
  { name: "Members", url: "/members" },
  { name: "Admin", url: "/admin" },
  { name: "404", url: "/404" },
];

app.use((req, res, next) => {
  app.locals.navLinks = navLinks;
  app.locals.currentURL = url.parse(req.url).pathname;
  next();
});

// Joi schema for validating user input
const schema = Joi.object({
  name: Joi.string().max(20).required(),
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

// Load environment variables
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = require("./databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + "/public"));

app.use(mongoSanitizer({ replaceWith: "_" }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}?retryWrites=true&w=majority`,
  crypto: {
    secret: mongodb_session_secret,
  },
  ttl: 60 * 60, // 1 hour in seconds (for MongoDB)
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
      maxAge: expireTime, // 1 hour in milliseconds
      httpOnly: true,
      secure: false, // false for localhost, true for HTTPS in production
      sameSite: "lax",
    },
  }),
);

app.get("/", (req, res) => {
  console.log(req.url);
  console.log(url.parse(req.url).pathname);
  res.render("index", {
    authenticated: req.session.authenticated,
    name: req.session.name,
  });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) {
    return res.send(
      `<h1>Error</h1> <p>Name is required.</p> <a href="/signup">Try again</a>`,
    );
  }
  if (!email) {
    return res.send(
      `<h1>Error</h1> <p>Please provide an email address.</p> <a href="/signup">Try again</a>`,
    );
  }
  if (!password) {
    return res.send(
      `<h1>Error</h1> <p>Password is required.</p> <a href="/signup">Try again</a>`,
    );
  }

  const validationResult = schema.validate({ name, email, password });

  if (validationResult.error != null) {
    const message = validationResult.error.details[0].message;
    res.send(
      `<h1>Error </h1> <p> ${message} </p> <a href="/signup">Try again</a>`,
    );
    return;
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const newUser = {
    name: name,
    email: email,
    password: hashedPassword,
    user_type: "user",
  };

  await userCollection.insertOne(newUser);

  req.session.authenticated = true;
  req.session.name = name;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime; // Now in milliseconds

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const validationResult = loginSchema.validate({ email, password });

  if (validationResult.error != null) {
    const message = validationResult.error.details[0].message;
    res.send(
      `<h1>Error </h1> <p> ${message} </p> <a href="/login">Try again</a>`,
    );
    return;
  }

  const user = await userCollection.findOne({ email: email });

  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.user_type = user.user_type;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
  } else {
    res.send(
      `<h1>Error </h1> <p> Invalid email/password combination </p> <a href="/login">Try again</a>`,
    );
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }

  // Logic to pick a random image between 1 and 3
  const imageNumber = Math.floor(Math.random() * 3) + 1;
  const imageName = "img" + imageNumber + ".jpg";

  res.render("members", {
    imageName: imageName,
    navLinks: navLinks,
    currentURL: url.parse(req.url).pathname,
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.get("/admin", async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }

  if (req.session.user_type !== "admin") {
    res.status(403).render("403");
    return;
  }

  const users = await userCollection.find().toArray();

  res.render("admin", { users: users, navLinks: navLinks });
});

app.post("/admin/promote/:userId", async (req, res) => {
  if (!req.session.authenticated || req.session.user_type !== "admin") {
    res.status(403).send("Not authorized");
    return;
  }

  const { ObjectId } = require("mongodb");
  await userCollection.updateOne(
    { _id: new ObjectId(req.params.userId) },
    { $set: { user_type: "admin" } },
  );

  res.redirect("/admin");
});

app.post("/admin/demote/:userId", async (req, res) => {
  if (!req.session.authenticated || req.session.user_type !== "admin") {
    res.status(403).send("Not authorized");
    return;
  }

  const { ObjectId } = require("mongodb");
  await userCollection.updateOne(
    { _id: new ObjectId(req.params.userId) },
    { $set: { user_type: "user" } },
  );

  res.redirect("/admin");
});

app.use((req, res) => {
  res.status(404).render("404");
});

const startServer = async () => {
  try {
    await database.connect();
    console.log("Successfully connected to MongoDB");

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error("Failed to connect to MongoDB", err);
    process.exit(1);
  }
};

startServer();
