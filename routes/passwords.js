const config = require("config");
const express = require("express");
const router = express.Router();
const auth = require("../middleware/auth");
const { createResource, getStore, updateResource, deleteResource } = require("../controller/passwords");

router.post("/", auth, createResource);

router.get("/", auth, getStore);

router.put("/:id", auth, updateResource);

router.delete("/:id", auth, deleteResource);

module.exports = router;
