const express = require("express");
const bcrypt = require("bcryptjs");
const db = require("../data/database");
const session = require("express-session");
const mongodb = require("mongodb");
const ObjectId = mongodb.ObjectId;

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

router.get("/profile", async function (req, res) {
  const user = req.session.user;
  const courses = await db
    .getDb()
    .collection("courses")
    .find({ email: user.email }, { title: 1, summary: 1, picture: 1 })
    .toArray();
  res.render("profile", { courses: courses, user: user });
});
router.get("/course", async function (req, res) {
  const courses = await db
    .getDb()
    .collection("courses")
    .find({}, { title: 1, summary: 1, picture: 1 })
    .toArray();
  res.render("course", { courses: courses });
});
router.get("/course/:id", async function (req, res) {
  const courseId = req.params.id;
  const course = await db
    .getDb()
    .collection("courses")
    .findOne({ _id: new ObjectId(courseId) }, { summary: 0 });
  res.render("course_inside", { course: course });
});
router.get("/about", function (req, res) {
  res.render("about");
});
router.get("/contact", function (req, res) {
  res.render("contact");
});
router.get("/addCourse", function (req, res) {
  res.render("addACourse");
});
router.post("/addCourse", async function (req, res) {
  const userData = req.body;
  const email = userData.email;
  const title = userData["title"];
  const authorName = userData.authorName;
  const authorYear = userData.authorYear;
  const summary = userData.summary;
  const description = userData.description;
  const price = userData.price;
  const picture = userData.picture;
  const learningOutcome = userData.learningOutcome;
  const mode = userData.mode;

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: email });
  if (existingUser) {
    const course = {
      email: email,
      title: title,
      authorName: authorName,
      authorYear: authorYear,
      summary: summary,
      description: description,
      price: price,
      picture: picture,
      learningOutcome: learningOutcome,
      mode: mode,
    };
    await db.getDb().collection("courses").insertOne(course);
    //alert("Your course has been added");
    req.flash("infoSubmit", "Course has been added");
    res.redirect("/addCourse");
  }
});
router.get("/internshipAndPlacements", async function (req, res) {
  const internships = await db
    .getDb()
    .collection("internships")
    .find({}, { title: 1, picture: 1 })
    .toArray();
  const placements = await db
    .getDb()
    .collection("placements")
    .find({}, { title: 1, picture: 1 })
    .toArray();
  res.render("internshipPlacements", {
    internships: internships,
    placements: placements,
  });
});
router.get("/internshipAndPlacements/:id", async function (req, res) {
  const infoId = req.params.id;
  const info = await db
    .getDb()
    .collection("internships")
    .findOne({ _id: new ObjectId(infoId) });
  if (info) {
    res.render("internship_inside", { internship: info });
  } else {
    const info2 = await db
      .getDb()
      .collection("placements")
      .findOne({ _id: new ObjectId(infoId) });
    res.render("internship_inside", { internship: info2 });
  }
});
router.post("/search", async (req, res) => {
  try {
    const locals = {
      title: "Search",
      description: "Simple Blog created with NodeJs, Express & MongoDb.",
    };

    let searchTerm = req.body.searchTerm;
    const searchNoSpecialChar = searchTerm.replace(/[^a-zA-Z0-9 ]/g, "");

    const data = await db
      .getDb()
      .collection("courses")
      .find({
        $or: [
          { title: { $regex: new RegExp(searchNoSpecialChar, "i") } },
          { body: { $regex: new RegExp(searchNoSpecialChar, "i") } },
        ],
      });

    res.render("search", {
      data: data,
      locals: locals,
      currentRoute: "/",
    });
  } catch (error) {
    console.log(error);
  }
});
router.get("/deleteCourse", async function (req, res) {
  const user = req.session.user;
  const courses = await db
    .getDb()
    .collection("courses")
    .find({ email: user.email }, { title: 1, summary: 1, picture: 1 })
    .toArray();
  res.render("deleteCourse", { courses: courses });
});
router.post("/deleteCourse/:id/delete", async function (req, res) {
  const courseId = new ObjectId(req.params.id);
  const result = await db
    .getDb()
    .collection("courses")
    .deleteOne({ _id: courseId });
  res.redirect("/deleteCourse");
});
router.post("/contact", async function (req, res) {
  const userData = req.body;
  const email = userData.email;
  const name = userData.name;
  const subject = userData.subject;
  const message = userData.message;
  if (!email || !name || !subject || !message) {
    req.session.inputData = {
      hasError: true,
      message: "Invalid input - please check your data",
      email: email,
      name: name,
      subject: subject,
      message: message,
    };
    req.session.save(function () {
      res.redirect("/contact");
    });
    return;
  }
  const contactDetail = {
    email: email,
    name: name,
    subject: subject,
    message: message,
  };
  await db.getDb().collection("contact").insertOne(contactDetail);
  res.redirect("/contact");
});

module.exports = router;
