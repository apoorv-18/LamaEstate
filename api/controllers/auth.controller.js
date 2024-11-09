import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../lib/prisma.js";


export const register = async (req, res) => {
  const { username, email, password } = req.body;

    // HASH THE PASSWORD
  try{
    const hashedPassword = await bcrypt.hash(password, 10);

    console.log(hashedPassword);

    const newUser = await prisma.user.create({
      data:{
        username,
        email,
        password:hashedPassword,
      }
    })
    console.log(newUser)
    res.status(201).json({message:"user created successfully"})
  }catch(err){
    res.status(500).json({message:"creation failed"})
  }
};

export const login = async (req, res) =>{
  const {username,password} = req.body;
  try{
      const user = await prisma.user.findUnique({
        where:{ username },
      })
      if(!user){
        res.status(401).json({message:"Invalid Credentials"})
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if(!isPasswordValid) return res.status(401).json({message:"Invalid Credentials"})

      const age = 1000*60*60*24*7;

      const token = jwt.sign({
        id:user.id,
      },process.env.JWT_SECRET_KEY,
      {expiresIn:age}
    );

    res.cookie("token",token,{
      httpOnly:true,
      // secure:true,
      maxAge:age,
    }).status(200).json({message:"login Successfull"})

  }catch(err){
    console.log(err)
    res.status(500).json({message:"failed to login"})
  }
}

export const logout = (req,res) => {
  try{res.clearCookie("token").status(200).json({message:"logout Successfull"})}
  catch(err){
    console.log(err)
  }
}