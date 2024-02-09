const path = require("path");

const express = require("express");
const session = require("express-session");
const mongodbStore = require("connect-mongodb-session");
const db = require("./server/data/database");
const demoRoutes = require("./server/routes/demo");
const flash = require("connect-flash");

const app = express();
const MongodbStore = mongodbStore(session);
const sessionStore = new MongodbStore({
  uri: "mongodb://127.0.0.1:27017",
  databaseName: "learning-endless",
  collection: "sessions",
});
app.use(
  session({
    secret: "super-secret",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
  })
);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.use(flash());

app.use(async function (req, res, next) {
  const user = req.session.user;
  const isAuth = req.session.isAuthenticated;
  if (!user || !isAuth) {
    return next();
  }
  const userDoc = await db
    .getDb()
    .collection("users")
    .findOne({ _id: user.id });
  const isTutor = userDoc.designation == "tutor";
  res.locals.isAuth = isAuth;
  res.locals.isTutor = isTutor;
  next();
});
app.use(demoRoutes);

//app.use(function (error, req, res, next) {
//res.render("500");
//});

db.connectToDatabase().then(function () {
  app.listen(3001);
});
