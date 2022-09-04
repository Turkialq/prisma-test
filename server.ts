import express, { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import * as dotenv from "dotenv";

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const prisma = new PrismaClient();

app.use(express.json());
dotenv.config();

const generateAcessToken = (user: any) => {
  return jwt.sign(user, process.env.ACESS_TOKEN_SECRET, { expiresIn: "15m" });
};

const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];
  if (token == null) return res.sendStatus(404);
  jwt.verify(
    token,
    process.env.ACESS_TOKEN_SECRET,
    (error: Error, user: any) => {
      if (error) return res.sendStatus(403);
      req.body.user = user;
      next();
    }
  );
};

app.post("/register", async (req: Request, res: Response) => {
  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    const userInfo = { name: req.body.name, password: hashedPassword };

    await prisma.users.create({
      data: {
        usernmae: userInfo.name,
        password: userInfo.password,
        role: {
          create: {
            role_name: "adminss",
            previlage_num: "100",
          },
        },
      },
    });
  } catch {
    res.status(500).send();
  }

  res.json("user has been registered in the system");
});

app.post("/login", async (req: Request, res: Response) => {
  try {
    const userInfo = { name: req.body.name, password: req.body.password };

    const user = await prisma.users.findFirst({
      where: {
        usernmae: userInfo.name,
      },
    });
    if (bcrypt.compare(userInfo.password, user?.password)) {
      const acessToken = generateAcessToken(user);
      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      await prisma.usedTokens.create({
        data: {
          Token: refreshToken,
        },
      });
      res.json({ acessToken: acessToken, refreshToken: refreshToken });
    }
  } catch {
    res.status(500).send();
  }
});

app.post(
  "/file-upload",
  authenticateToken,
  async (req: Request, res: Response) => {
    res.json("file-upload workes");
  }
);

app.post("/refresh-token", async (req: Request, res: Response) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  const isThereToken = await prisma.usedTokens.findFirst({
    where: {
      Token: refreshToken,
    },
  });
  if (isThereToken == null) return res.sendStatus(403);
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    (error: Error, user: any) => {
      if (error) return res.sendStatus(403);
      const acessToken = generateAcessToken({ name: user.name });
      res.json({ acessToken: acessToken });
    }
  );
});

app.delete("/logout", async (req: Request, res: Response) => {
  const deletedToken = req.body.token;

  const isThereToken = await prisma.usedTokens.findFirst({
    where: {
      Token: deletedToken,
    },
  });

  if (isThereToken) {
    await prisma.usedTokens.delete({
      where: {
        id: isThereToken.id,
      },
    });
    res.sendStatus(204);
  }
});

app.listen(8080, () => {
  console.log("Server on port 8080!");
});
