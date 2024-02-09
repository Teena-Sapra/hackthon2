const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("../data/database");
const session = require("express-session");

const router = express.Router();

router.get("/", function (req, res) {
  res.render("index");
});

router.get("/signup", function (req, res) {
  //signup
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      confirmEmail: "",
      password: "",
      confirmPassword: "",
    };
  }
  req.session.inputData = null;
  res.render("signup", { inputData: sessionInputData });
});

router.get("/login", function (req, res) {
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      password: "",
    };
  }
  req.session.inputData = null;
  res.render("login", { inputData: sessionInputData });
});

router.post("/signup", async function (req, res) {
  const userData = req.body;
  const email = userData.email;
  const confirmEmail = userData["confirm-email"];
  const password = userData.password;
  const confirmPassword = userData.confirmPassword;
  const designation = userData.designation;
  if (
    !email ||
    !confirmEmail ||
    !password ||
    !confirmPassword ||
    password.trim() < 6 ||
    email != confirmEmail ||
    !email.includes("@") ||
    password != confirmPassword
  ) {
    req.session.inputData = {
      hasError: true,
      message: "Invalid input - please check your data",
      email: email,
      confirmEmail: confirmEmail,
      password: password,
      confirmPassword: confirmPassword,
      designation: designation,
    };
    req.session.save(function () {
      res.redirect("/signup");
    });
    return;
  }
  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });
  if (existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "User exists already",
      email: email,
      confirmEmail: confirmEmail,
      password: password,
      confirmPassword: confirmPassword,
      desgination: designation,
    };
    req.session.save(function () {
      res.redirect("/signup");
    });
    return;
  }
  const hashedPassword = await bcrypt.hash(password, 12);
  const user = {
    email: email,
    password: hashedPassword,
    designation: designation,
  };
  await db.getDb().collection("users").insertOne(user);
  res.redirect("/login");
});

router.post("/login", async function (req, res) {
  const userData = req.body;
  const email = userData.email;
  const password = userData.password;
  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });
  if (!existingUser) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your credentials",
      email: email,
      password: password,
    };
    req.session.save(function () {
      res.redirect("/login");
    });
    return;
  }
  const passwordAreEqual = await bcrypt.compare(
    password,
    existingUser.password
  );
  if (!passwordAreEqual) {
    req.session.inputData = {
      hasError: true,
      message: "Could not log you in - please check your credentials",
      email: email,
      password: password,
    };
    req.session.save(function () {
      res.redirect("/login");
    });
    return;
  }
  req.session.user = {
    id: existingUser._id,
    email: existingUser.email,
  };
  req.session.isAuthenticated = true;
  req.session.save(function () {
    res.redirect("/");
  });
});

router.get("/admin", async function (req, res) {
  if (!res.locals.isAuth) {
    return res.status(401).render("401");
  }
  if (!res.locals.isTutor) {
    return res.status(403).render("403");
  }
  res.render("admin");
});

router.post("/logout", function (req, res) {
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

router.get("/profile", function (req, res) {
  if (!res.locals.isAuth) {
    return res.status(401).render("401");
  }
  res.render("profile");
});
router.get("/course", async function (req, res) {
  const courses = await db
    .getDb()
    .collection("courses")
    .find({}, { title: 1, summary: 1, picture: 1 })
    .toArray();
  res.render("course", { courses: courses });
});
router.get("/about", function (req, res) {
  res.render("about");
});
router.get("/contact", function (req, res) {
  res.render("contact");
});

module.exports = router;
