import express from "express";
import userRouter from "../src/routes/userRoute";

const app = express();
app.use(express.json());

app.use("/api/v1/users", userRouter);

app.listen(process.env.PORT || 8000, () => {
  console.log("Congrats! Server started on port 8000");
});
