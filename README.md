Hello , In this project i have developed a ML based password strength analyzer that is useful to Accurately determine The strength of the password.


* IMPORTANT!!!
  ------------

The only way for this project to work on ur system is when both "Main.py" and "NewModelRF_v2.joblib" to be in the same directory , the code "Main.py" automatically 
retrieves ur model's path before executing.


* HOW I TRAINED THE MODEL
  -----------------------

The Model that i have used is Random Forest since It Handles Multiple Features Effectively,Robustness Against Overfitting, Support for Categorical and Numerical Data and many 
more but these were the main features that made me use Random Forest algo. The model was mainly trained using data set taken from kaggle which had around 670K different passwords
along with its strength(Weak , Moderate , Strong and Very Strong) and also different features like ["length" , "has_uppercase" , "had_lowercase" , "has_digits" , "has_special"
, "has_unique_chars" ,  "has_entropy" , "has_sequential" , "has_repitition" , "strength_label" ] were further added into the data set on which it was initially trained , later on a data set 
that had common passwords used in the world that is vulnerable against dictionary attacks were used to further train the model to accurately give the strength score if the user gives a password
that was too common and were related/ found in any recent dictionary attacks the strength score is decremented.

* FEATURES INCLUDED
  -----------------

  The "Main.py" checks the following features for the given password ["length" , "has_uppercase" , "had_lowercase" , "has_digits" , "has_special" , "has_unique_chars" ,
  "has_entropy" , "has_sequential" , "has_repitition" , "strength_label" ]

  
